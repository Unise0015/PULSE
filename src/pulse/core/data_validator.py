import re
from enum import Enum
from typing import List, Optional, Tuple
from pulse.domain.models import VulnerabilityFinding

class FindingRejectReason(str, Enum):
    INVALID_CVE = "INVALID_CVE"
    INVALID_CVSS = "INVALID_CVSS"
    INVALID_EPSS = "INVALID_EPSS"
    INVALID_CWE = "INVALID_CWE"
    DUPLICATE = "DUPLICATE"
    PROVIDER_ERROR = "PROVIDER_ERROR"
    MALFORMED_RESPONSE = "MALFORMED_RESPONSE"

CVE_REGEX = re.compile(r"^CVE-\d{4}-\d{4,}$")
CWE_REGEX = re.compile(r"^CWE-\d+$")

class VulnerabilityDataValidator:
    """Validates vulnerability findings against security intelligence standards."""

    @staticmethod
    def validate_cve_id(cve_id: Optional[str]) -> Tuple[bool, Optional[FindingRejectReason]]:
        if not cve_id or not isinstance(cve_id, str):
            return False, FindingRejectReason.INVALID_CVE
        if not CVE_REGEX.match(cve_id.strip()):
            return False, FindingRejectReason.INVALID_CVE
        return True, None

    @staticmethod
    def validate_cvss_score(score: Optional[float]) -> Tuple[bool, Optional[FindingRejectReason]]:
        if score is None:
            return True, None  # None CVSS is handled as optional warning, not rejection
        try:
            val = float(score)
            if 0.0 <= val <= 10.0:
                return True, None
            return False, FindingRejectReason.INVALID_CVSS
        except (ValueError, TypeError):
            return False, FindingRejectReason.INVALID_CVSS

    @staticmethod
    def validate_epss_score(score: Optional[float]) -> Tuple[bool, Optional[FindingRejectReason]]:
        if score is None:
            return True, None
        try:
            val = float(score)
            if 0.0 <= val <= 1.0:
                return True, None
            return False, FindingRejectReason.INVALID_EPSS
        except (ValueError, TypeError):
            return False, FindingRejectReason.INVALID_EPSS

    @staticmethod
    def validate_cwe_id(cwe: Optional[str]) -> Tuple[bool, Optional[FindingRejectReason]]:
        if not cwe:
            return True, None  # Optional field
        if not isinstance(cwe, str) or not CWE_REGEX.match(cwe.strip()):
            return False, FindingRejectReason.INVALID_CWE
        return True, None

    @classmethod
    def validate_finding(cls, finding: VulnerabilityFinding) -> Tuple[bool, List[str], List[FindingRejectReason]]:
        """
        Validates a VulnerabilityFinding.
        Returns: (is_valid, warnings, rejection_reasons)
        """
        warnings: List[str] = []
        rejections: List[FindingRejectReason] = []

        cve_valid, cve_err = cls.validate_cve_id(finding.cve_id)
        if not cve_valid and cve_err:
            rejections.append(cve_err)
            warnings.append(f"Invalid CVE format: {finding.cve_id}")

        cvss_valid, cvss_err = cls.validate_cvss_score(finding.cvss_score)
        if not cvss_valid and cvss_err:
            rejections.append(cvss_err)
            warnings.append(f"Invalid CVSS score range: {finding.cvss_score}")

        epss_valid, epss_err = cls.validate_epss_score(finding.epss_score)
        if not epss_valid and epss_err:
            rejections.append(epss_err)
            warnings.append(f"Invalid EPSS probability range: {finding.epss_score}")

        cwe_valid, cwe_err = cls.validate_cwe_id(finding.cwe)
        if not cwe_valid and cwe_err:
            rejections.append(cwe_err)
            warnings.append(f"Invalid CWE identifier format: {finding.cwe}")

        if not finding.description:
            warnings.append(f"Missing description for finding {finding.cve_id}")

        is_valid = len(rejections) == 0
        return is_valid, warnings, rejections
