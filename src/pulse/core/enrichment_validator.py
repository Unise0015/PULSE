import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

from pulse.domain.models import ScanResult, VulnerabilityFinding
from pulse.core.data_validator import VulnerabilityDataValidator, FindingRejectReason
from pulse.core.provider_health import ProviderStatus, ProviderHealth

logger = logging.getLogger(__name__)

class ScanIntegrity(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

@dataclass
class EnrichmentProvenance:
    """Provenance tracking origin of intelligence fields per finding."""
    cve_id: str
    osv_found: bool = False
    nvd_found: bool = False
    epss_found: bool = False
    kev_found: bool = False
    cvss_source: str = "Unknown"
    severity_source: str = "Unknown"
    description_source: str = "Unknown"
    cwe_source: str = "Unknown"
    missing_fields: List[str] = field(default_factory=list)


@dataclass
class ValidationSummary:
    valid_cves_count: int = 0
    valid_cvss_count: int = 0
    missing_cwe_count: int = 0
    missing_description_count: int = 0
    duplicate_count: int = 0
    invalid_cve_count: int = 0
    invalid_cvss_count: int = 0
    invalid_epss_count: int = 0
    invalid_cwe_count: int = 0
    malformed_payload_count: int = 0
    rejection_reasons: Dict[str, int] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)

    @property
    def validation_failures_count(self) -> int:
        """Count of strict validation failures (excluding duplicates)."""
        return (
            self.invalid_cve_count +
            self.invalid_cvss_count +
            self.invalid_epss_count +
            self.invalid_cwe_count +
            self.malformed_payload_count +
            self.rejection_reasons.get(FindingRejectReason.PROVIDER_ERROR.value, 0)
        )


class EnrichmentConsistencyValidator:
    """Validates cross-provider relationships and computes deterministic ScanIntegrity."""

    @classmethod
    def analyze_provenance(cls, finding: VulnerabilityFinding) -> EnrichmentProvenance:
        missing: List[str] = []
        if not finding.cvss_score:
            missing.append("CVSS")
        if not finding.cwe:
            missing.append("CWE")
        if not finding.description:
            missing.append("Description")

        source_str = finding.source or "OSV"
        nvd_found = "nvd" in source_str.lower() or finding.nvd_url is not None
        osv_found = True

        return EnrichmentProvenance(
            cve_id=finding.cve_id,
            osv_found=osv_found,
            nvd_found=nvd_found,
            epss_found=finding.epss_score is not None and finding.epss_score > 0,
            kev_found=finding.kev_match,
            cvss_source="NVD" if nvd_found else "OSV",
            severity_source="NVD" if nvd_found else "Calculated",
            description_source="OSV",
            cwe_source="NVD" if finding.cwe else "None",
            missing_fields=missing
        )

    @classmethod
    def validate_scan_findings(cls, scan: ScanResult) -> Tuple[ValidationSummary, List[EnrichmentProvenance]]:
        summary = ValidationSummary()
        provenances: List[EnrichmentProvenance] = []
        seen_cves: Set[str] = set()

        for finding in scan.findings:
            prov = cls.analyze_provenance(finding)
            provenances.append(prov)

            # Check duplicates
            dedup_key = f"{finding.package.name}@{finding.package.version}:{finding.cve_id}" if finding.package else finding.cve_id
            if dedup_key in seen_cves:
                summary.duplicate_count += 1
                summary.rejection_reasons[FindingRejectReason.DUPLICATE.value] = summary.rejection_reasons.get(FindingRejectReason.DUPLICATE.value, 0) + 1
            else:
                seen_cves.add(dedup_key)

            # Validate finding data
            is_valid, warnings, rejections = VulnerabilityDataValidator.validate_finding(finding)
            summary.warnings.extend(warnings)

            if is_valid:
                summary.valid_cves_count += 1
                if finding.cvss_score is not None:
                    summary.valid_cvss_count += 1
            else:
                for r in rejections:
                    r_val = r.value
                    summary.rejection_reasons[r_val] = summary.rejection_reasons.get(r_val, 0) + 1
                    if r == FindingRejectReason.INVALID_CVE:
                        summary.invalid_cve_count += 1
                    elif r == FindingRejectReason.INVALID_CVSS:
                        summary.invalid_cvss_count += 1
                    elif r == FindingRejectReason.INVALID_EPSS:
                        summary.invalid_epss_count += 1
                    elif r == FindingRejectReason.INVALID_CWE:
                        summary.invalid_cwe_count += 1
                    elif r == FindingRejectReason.MALFORMED_RESPONSE:
                        summary.malformed_payload_count += 1

            if not finding.cwe:
                summary.missing_cwe_count += 1
            if not finding.description:
                summary.missing_description_count += 1

        return summary, provenances

    @classmethod
    def calculate_scan_integrity(
        cls,
        provider_health_map: Dict[str, ProviderHealth],
        summary: ValidationSummary,
        total_findings: int
    ) -> Tuple[ScanIntegrity, List[str]]:
        reasons: List[str] = []

        statuses = [p.status for p in provider_health_map.values()]
        offline_count = sum(1 for s in statuses if s == ProviderStatus.OFFLINE)
        error_count = sum(1 for s in statuses if s == ProviderStatus.ERROR)
        partial_count = sum(1 for s in statuses if s == ProviderStatus.PARTIAL)

        missing_enrichment_pct = 0.0
        if total_findings > 0:
            missing_count = sum(1 for w in summary.warnings if "Missing" in w or "NVD" in w)
            missing_enrichment_pct = (missing_count / total_findings) * 100.0

        val_failures = summary.validation_failures_count

        if offline_count > 1 or error_count > 0 or missing_enrichment_pct > 25.0 or val_failures > 0:
            integrity = ScanIntegrity.LOW
            if val_failures > 0:
                reasons.append(f"{val_failures} validation failure(s) detected")
            if offline_count > 1 or error_count > 0:
                reasons.append("Multiple intelligence providers offline or error")
            if missing_enrichment_pct > 25.0:
                reasons.append(f"{round(missing_enrichment_pct, 1)}% findings missing enrichment")
        elif partial_count >= 1 or offline_count == 1 or missing_enrichment_pct >= 5.0:
            integrity = ScanIntegrity.MEDIUM
            if offline_count == 1:
                p_off = [p.provider for p in provider_health_map.values() if p.status == ProviderStatus.OFFLINE]
                reasons.append(f"Provider {', '.join(p_off)} unavailable")
            if partial_count >= 1:
                reasons.append("Partial enrichment from secondary providers")
            if missing_enrichment_pct >= 5.0:
                reasons.append(f"{round(missing_enrichment_pct, 1)}% findings missing enrichment")
            if summary.warnings:
                reasons.append(f"{len(summary.warnings)} validation warning(s)")
        else:
            integrity = ScanIntegrity.HIGH
            reasons.append("All intelligence providers healthy")

        return integrity, reasons
