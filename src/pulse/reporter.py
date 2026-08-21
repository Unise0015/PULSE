import json
import dataclasses
from datetime import datetime
from pathlib import Path

from pulse.domain.models import ScanResult, VulnerabilityFinding, PackageInfo
from pulse import __version__
from pulse.reporting.context import ReportContext
from pulse.reporting.builder import ReportBuilder
from pulse.reporting.renderers import (
    JSONRenderer, MarkdownRenderer, HTMLRenderer, TextRenderer
)

class EnhancedJSONEncoder(json.JSONEncoder):
    def default(self, o):
        from enum import Enum
        if isinstance(o, Enum):
            return o.value
        if dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)
        if isinstance(o, datetime):
            return o.isoformat()
        return super().default(o)

def generate_mock_scan_data() -> ScanResult:
    """Generate a sample ScanResult with mock data for testing exports."""
    pkg1 = PackageInfo(name="openssl", version="3.0.1", ecosystem="system-apt")
    pkg2 = PackageInfo(name="requests", version="2.27.0", ecosystem="python")
    
    finding1 = VulnerabilityFinding(
        package=pkg1,
        cve_id="CVE-2022-0778",
        cvss_score=9.8,
        cvss_severity="CRITICAL",
        epss_score=0.97,
        epss_percent="97%",
        kev_match=True,
        risk_heat_score=89,
        description="Infinite loop in BN_mod_sqrt() reachable when parsing certificates",
        fix_version="3.0.7",
        source="OSV",
        published_date="2022-03-15T00:00:00",
        last_modified_date="2022-03-20T00:00:00",
        nvd_url="https://nvd.nist.gov/vuln/detail/CVE-2022-0778"
    )
    
    finding2 = VulnerabilityFinding(
        package=pkg2,
        cve_id="CVE-2023-32681",
        cvss_score=7.5,
        cvss_severity="HIGH",
        epss_score=0.04,
        epss_percent="4%",
        kev_match=False,
        risk_heat_score=45,
        description="Requests leaks Proxy-Authorization headers to destination servers when redirected to an HTTPS endpoint",
        fix_version="2.31.0",
        source="OSV",
        published_date="2023-05-26T00:00:00",
        last_modified_date="2023-06-01T00:00:00",
        nvd_url="https://nvd.nist.gov/vuln/detail/CVE-2023-32681"
    )
    
    scan = ScanResult(
        timestamp=datetime.now(),
        hostname="dev-machine",
        tool_version=__version__,
        packages_scanned=492,
        attack_surface_score=63,
        scan_duration_seconds=12.5,
        findings=[finding1, finding2]
    )
    return scan

import os
from typing import Union

class ReportExportError(Exception):
    """Raised when report export destination path fails validation."""
    pass

def validate_export_path(output_path: Union[str, Path], default_filename: str = "report") -> Path:
    """Validates export path permissions and resolves target path using ReportPathResolver."""
    raw_p = Path(output_path)
    if raw_p.exists() and raw_p.is_dir():
        raise ReportExportError(f"Unable to write report: Export target '{raw_p}' is a directory.")

    from pulse.reporting.path_resolver import ReportPathResolver
    path = ReportPathResolver.resolve(filename_or_base=default_filename, explicit_path=output_path)
    try:
        parent = path.parent
        parent.mkdir(parents=True, exist_ok=True)
        
        if not path.exists():
            test_file = parent / f".perm_check_{path.name}.tmp"
            try:
                with open(test_file, "w") as f:
                    f.write("test")
                if test_file.exists():
                    test_file.unlink()
            except (PermissionError, OSError):
                raise ReportExportError(f"Unable to write report: Permission denied for directory '{parent}'. Choose another directory.")
        else:
            if path.is_dir():
                raise ReportExportError(f"Unable to write report: Export target '{path}' is a directory.")
            try:
                with open(path, "a") as f:
                    pass
            except (PermissionError, OSError):
                raise ReportExportError(f"Unable to write report: Target file '{path}' is read-only or locked. Choose another directory.")
    except ReportExportError:
        raise
    except (PermissionError, FileNotFoundError, OSError) as e:
        raise ReportExportError(f"Unable to write report: {e}. Choose another directory.")

    return path

def export_json(scan: ScanResult, output_path: Path):
    """Export ScanResult to JSON format matching PRD & canonical schema 2.0."""
    valid_path = validate_export_path(output_path)
    ctx = ReportContext(scan_result=scan, scan_id="export")
    model = ReportBuilder.build(ctx)
    renderer = JSONRenderer()
    content = renderer.render(model)

    from pulse.core.provider_health import provider_tracker
    from pulse.core.enrichment_validator import EnrichmentConsistencyValidator

    health_map = provider_tracker.get_all_health()
    summary, provs = EnrichmentConsistencyValidator.validate_scan_findings(scan)
    integrity, reasons = EnrichmentConsistencyValidator.calculate_scan_integrity(health_map, summary, len(scan.findings))

    mapped_att = sum(1 for f in scan.findings if getattr(f, "attack_techniques", None))
    mapped_cwe = sum(1 for f in scan.findings if getattr(f, "cwe_id", None))

    output_dict = json.loads(content)
    output_dict["scan_meta"] = {
        "timestamp": scan.timestamp.isoformat() if scan.timestamp else datetime.now().isoformat(),
        "hostname": scan.hostname,
        "tool_version": scan.tool_version,
        "packages_scanned": scan.packages_scanned,
        "attack_surface_score": scan.attack_surface_score,
        "execution_duration_seconds": getattr(scan, "scan_duration_seconds", 0.0),
        "scan_integrity": integrity.value,
        "integrity_reasons": reasons,
        "att_ck_coverage": {
            "mapped": mapped_att,
            "total": len(scan.findings),
            "unmapped": len(scan.findings) - mapped_att
        },
        "cwe_coverage": {
            "mapped": mapped_cwe,
            "total": len(scan.findings),
            "unmapped": len(scan.findings) - mapped_cwe
        }
    }
    output_dict["provider_statistics"] = {
        p_name: {
            "status": p.status.value,
            "duration_ms": p.duration_ms,
            "cache_hits": p.cache_hits,
            "cache_misses": p.cache_misses,
            "network_requests": p.network_requests,
            "records_enriched": p.records_enriched,
            "records_requested": p.records_requested,
            "warnings": p.warnings
        }
        for p_name, p in health_map.items()
    }
    output_dict["validation_summary"] = {
        "valid_cves": summary.valid_cves_count,
        "valid_cvss": summary.valid_cvss_count,
        "missing_cwe": summary.missing_cwe_count,
        "missing_description": summary.missing_description_count,
        "duplicate_findings": summary.duplicate_count,
        "validation_failures": summary.validation_failures_count
    }
    output_dict["summary"] = {
        "vulnerable": scan.vulnerable_packages_count,
        "clean": scan.clean_packages_count,
        "critical": scan.severity_counts.get("CRITICAL", 0),
        "high": scan.severity_counts.get("HIGH", 0),
        "medium": scan.severity_counts.get("MEDIUM", 0),
        "low": scan.severity_counts.get("LOW", 0),
        "kev_matches": scan.kev_matches_count
    }

    with open(valid_path, "w", encoding="utf-8") as f:
        json.dump(output_dict, f, indent=2, ensure_ascii=False, cls=EnhancedJSONEncoder)

def export_attack_paths_json(scan: ScanResult, output_path: Path):
    """Export Attack Paths to a JSON file."""
    valid_path = validate_export_path(output_path)
    output_dict = {
        "attack_paths": [dataclasses.asdict(p) for p in getattr(scan, "attack_paths", [])]
    }
    with open(valid_path, "w", encoding="utf-8") as f:
        json.dump(output_dict, f, indent=2, ensure_ascii=False, cls=EnhancedJSONEncoder)

def export_exploit_intelligence_json(scan: ScanResult, output_path: Path):
    """Export dedicated Exploit Intelligence report containing ONLY confirmed PoC findings."""
    valid_path = validate_export_path(output_path)
    from pulse.ui import has_confirmed_public_poc
    poc_findings = [f for f in scan.findings if has_confirmed_public_poc(f)]
    output_dict = {
        "exploit_intelligence": [
            {
                "cve_id": f.cve_id,
                "package": f.package.name if f.package else "Unknown",
                "version": f.package.version if f.package else "Unknown",
                "severity": f.cvss_severity,
                "cvss_score": f.cvss_score,
                "epss_percent": f.epss_percent,
                "kev_match": f.kev_match,
                "public_poc": True,
                "poc_source": f.exploit_intelligence.poc_source if f.exploit_intelligence else None,
                "exploit_maturity": f.exploit_intelligence.exploit_maturity if f.exploit_intelligence else None,
                "exploit_references": f.exploit_intelligence.exploit_references if f.exploit_intelligence else []
            }
            for f in poc_findings
        ]
    }
    with open(valid_path, "w", encoding="utf-8") as f:
        json.dump(output_dict, f, indent=2, ensure_ascii=False, cls=EnhancedJSONEncoder)

def export_markdown(scan: ScanResult, output_path: Path):
    """Export ScanResult to Markdown report format."""
    valid_path = validate_export_path(output_path)
    ctx = ReportContext(scan_result=scan, scan_id="export")
    model = ReportBuilder.build(ctx)
    renderer = MarkdownRenderer()
    content = renderer.render(model)
    with open(valid_path, "w", encoding="utf-8") as f:
        f.write(content)

def export_csv(scan_result: ScanResult, output_path: str):
    valid_path = validate_export_path(output_path)
    import csv
    from pulse.vulnerability.cwe_registry import CWERegistry
    with open(valid_path, "w", newline='', encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "package", "version", "cve_id", "cwe_id", "cwe_name", "cvss_score", "epss_score", 
            "kev_match", "risk_heat_score", "severity", "fix_version", "recommended_version", "remediation_command", "attack_techniques", "source"
        ])
        for finding in scan_result.findings:
            rec = scan_result.get_recommendation(finding.package.name, finding.package.ecosystem) if finding.package else None
            rec_ver = rec.recommended_version if rec else finding.fix_version
            cmd = rec.upgrade_command if rec else ""
            cwe_name = finding.cwe_name or CWERegistry.resolve_name(finding.cwe_id) or ""
            
            att_str = ""
            if getattr(finding, "attack_techniques", None):
                att_str = "; ".join([f"{t.technique_id} — {getattr(t, 'technique_name', None) or 'Technique name unavailable'}" for t in finding.attack_techniques])

            writer.writerow([
                finding.package.name if finding.package else "Unknown",
                finding.package.version if finding.package else "Unknown",
                finding.cve_id,
                finding.cwe_id or "",
                cwe_name,
                finding.cvss_score,
                finding.epss_percent,
                "YES" if finding.kev_match else "NO",
                finding.risk_heat_score,
                finding.cvss_severity,
                finding.fix_version or "",
                rec_ver or "",
                cmd or "",
                att_str,
                finding.source
            ])

def export_html(scan: ScanResult, output_path: Path, delta=None, advisor=None):
    """Export ScanResult to commercial HTML security dashboard."""
    valid_path = validate_export_path(output_path)
    ctx = ReportContext(scan_result=scan, scan_id="export", posture_delta=delta, advisor=advisor)
    model = ReportBuilder.build(ctx)
    renderer = HTMLRenderer()
    content = renderer.render(model)
    with open(valid_path, "w", encoding="utf-8") as f:
        f.write(content)

