"""Pure website view data: rendering must never resolve packages or call providers."""
from dataclasses import dataclass
from typing import List

from pulse.domain.models import CorrelationStatus, ScanResult, TechnologyFingerprint


def value(item) -> str:
    return str(getattr(item, "value", item))


@dataclass
class TechnologyView:
    technology: TechnologyFingerprint
    status: str
    reason: str
    findings: list
    checked: bool

    @property
    def label(self) -> str:
        return {
            "VULNERABILITIES_FOUND": "Vulnerabilities found",
            "NO_KNOWN_VULNERABILITIES": "No known vulnerabilities",
            "VERSION_REQUIRED": "Version required",
            "DETECTION_ONLY": "Detection only",
            "NOT_RUN": "Not checked",
            "CORRELATION_UNAVAILABLE": "Check incomplete",
        }.get(self.status, self.status.replace("_", " ").capitalize())


def technology_views(scan: ScanResult) -> List[TechnologyView]:
    assessment = scan.website_assessment
    if not assessment:
        return []
    rows = []
    recorded = {name.casefold(): result for name, result in assessment.technology_correlation_results.items()}
    for tech in sorted(assessment.technologies, key=lambda t: (-t.confidence, t.name.lower())):
        result = recorded.get(tech.name.casefold())
        eligibility = assessment.technology_eligibilities.get(tech.signature_id or tech.name.lower())
        findings = list(result.vulnerabilities) if result else [
            f for f in scan.findings if (f.source_asset or "").casefold() == tech.name.casefold()
        ]
        if findings:
            status, reason = "VULNERABILITIES_FOUND", f"{len(findings)} recorded findings; review remediation."
        elif result:
            status, reason = result.correlation_status, result.correlation_reason
            if status == "VULNERABILITIES_FOUND":
                status, reason = "CORRELATION_UNAVAILABLE", "Finding details are unavailable; run correlation again."
        elif not tech.version or tech.version.strip().lower() == "unknown":
            status, reason = "VERSION_REQUIRED", "Confirm the deployed version before matching vulnerabilities."
        elif eligibility and not eligibility.is_eligible:
            status, reason = value(eligibility.status), eligibility.reason
        else:
            status = "NOT_RUN"
            reason = "No per-technology check was recorded. Run Correlate Technologies."
        rows.append(TechnologyView(tech, status, reason, findings, status in (
            "VULNERABILITIES_FOUND", "NO_KNOWN_VULNERABILITIES")))
    return rows


def can_correlate(scan: ScanResult) -> bool:
    assessment = scan.website_assessment
    return bool(assessment and assessment.status in ("OK", "PARTIAL") and assessment.technologies)


def next_step(scan: ScanResult) -> str:
    assessment = scan.website_assessment
    if not assessment:
        return "Run a website assessment."
    if assessment.status == "OFFLINE":
        return "Disable offline mode and scan the website again."
    if assessment.status in ("ERROR", "INVALID"):
        return "Check the URL and connection, then scan again. Header checks are unavailable."
    if not assessment.technologies:
        return "No technologies detected. Confirm the page is accessible; fingerprinting cannot identify every stack."
    if assessment.correlation_status == CorrelationStatus.NOT_RUN:
        return "Run Correlate Technologies to check detected versions for known vulnerabilities."
    if assessment.correlation_status in (CorrelationStatus.PARTIAL, CorrelationStatus.FAILED):
        return "Review coverage warnings and retry correlation when intelligence sources are available."
    if scan.findings:
        return "Review vulnerabilities and remediation, prioritizing the highest risk findings."
    return "Review unchecked technologies and security headers. No known findings is not a guarantee of security."
