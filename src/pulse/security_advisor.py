"""
Security Advisor Engine — analyzes a ScanResult and produces a prioritized
remediation report with package health status, risk projections, and action plans.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from pulse.domain.models import ScanResult, VulnerabilityFinding
from pulse.ui import get_recommended_command


# ── Data Classes ───────────────────────────────────────────────────────────────

@dataclass
class PackageAction:
    """A single prioritized upgrade action for one package."""
    name: str
    ecosystem: str
    installed: str
    min_safe: Optional[str]       # Minimum version that patches all known CVEs
    target: Optional[str]         # Latest stable version from registry
    cve_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    max_risk: int
    recommended_command: str      # pip install --upgrade pkg


@dataclass
class SecurityAdvisorReport:
    """Full security advisory generated from a ScanResult."""
    actions: List[PackageAction]          # Sorted by impact (max_risk desc)

# ── Version utilities ──────────────────────────────────────────────────────────

def _parse_major(version: Optional[str]) -> Optional[int]:
    """Extract the leading integer from a version string."""
    if not version:
        return None
    m = re.match(r"(\d+)", version.strip())
    return int(m.group(1)) if m else None


def classify_package_status(installed: str, latest: Optional[str]) -> str:
    """
    Classify a package's support lifecycle status based on version distance.

    Rules (heuristic — no external EOL database required):
    - latest unknown        → Unknown
    - installed_major < latest_major - 1  → EOL
    - installed_major == latest_major - 1 → Maintenance
    - same major, behind on minor/patch   → Supported (with update available)
    - up to date                          → Supported
    """
    if not latest:
        return "Unknown"

    inst_major = _parse_major(installed)
    lat_major  = _parse_major(latest)

    if inst_major is None or lat_major is None:
        return "Unknown"

    gap = lat_major - inst_major
    if gap >= 2:
        return "EOL"
    if gap == 1:
        return "Maintenance"
    return "Supported"


# ── Core Advisor ───────────────────────────────────────────────────────────────

class SecurityAdvisor:
    """Analyses a ScanResult and generates a SecurityAdvisorReport."""

    def analyze(self, scan: ScanResult) -> SecurityAdvisorReport:
        if not scan.findings:
            return SecurityAdvisorReport(
                actions=[]
            )

        from pulse.vulnerability.version_intelligence import VersionIntelligenceService
        from pulse.domain.data_validation import VersionIntegrityValidator

        version_intel = VersionIntelligenceService()

        # Aggregate findings per package
        pkg_map: Dict[str, dict] = {}
        for f in scan.findings:
            key = f"{f.package.ecosystem}:{f.package.name}"
            if key not in pkg_map:
                pkg_map[key] = {
                    "package":      f.package,
                    "max_risk":     f.risk_heat_score,
                    "cves":         [],
                }
            entry = pkg_map[key]
            entry["cves"].append(f)
            if f.risk_heat_score > entry["max_risk"]:
                entry["max_risk"] = f.risk_heat_score

        # Build PackageAction list sorted by max_risk desc
        actions: List[PackageAction] = []
        for entry in sorted(pkg_map.values(), key=lambda x: x["max_risk"], reverse=True):
            package = entry["package"]
            cves = entry["cves"]

            rec = None
            if package.version_metadata:
                rec = version_intel.get_security_fix_version(package, package.version, cves)
                res = version_intel.fetch_version_data(package.ecosystem, package.name, offline=True)
                versions = res.get("versions", [])
                VersionIntegrityValidator.validate_metadata(package.ecosystem, package.version_metadata, versions)

            if rec and rec.minimum_safe_version:
                min_safe = rec.minimum_safe_version
                for f in cves:
                    f.fix_version = min_safe
            else:
                max_f = max(cves, key=lambda x: x.risk_heat_score)
                min_safe = max_f.fix_version

            target = (package.version_metadata.latest_stable_version if package.version_metadata else None) or package.latest_version or min_safe

            sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            for f in cves:
                sev = f.cvss_severity.upper()
                if sev in sev_counts:
                    sev_counts[sev] += 1

            actions.append(PackageAction(
                name=package.name,
                ecosystem=package.ecosystem,
                installed=package.version,
                min_safe=min_safe,
                target=target,
                cve_count=len(cves),
                critical_count=sev_counts["CRITICAL"],
                high_count=sev_counts["HIGH"],
                medium_count=sev_counts["MEDIUM"],
                low_count=sev_counts["LOW"],
                max_risk=entry["max_risk"],
                recommended_command=get_recommended_command(
                    package.name, package.ecosystem
                ),
            ))

        return SecurityAdvisorReport(
            actions=actions
        )
