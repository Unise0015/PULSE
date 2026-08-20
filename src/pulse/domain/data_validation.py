import re
import logging
from typing import List, Dict, Any, Optional
from pulse.domain.models import VulnerabilityFinding
from pulse.domain.version import get_comparator

logger = logging.getLogger(__name__)

class VulnerabilityDataValidator:
    """Validates data integrity, sources, and correctness of vulnerability findings."""
    
    CVE_REGEX = re.compile(r'^CVE-\d{4}-\d{4,}$')
    
    @classmethod
    def validate_cve_format(cls, cve_id: str) -> bool:
        """Validates if a CVE ID matches the official format."""
        if not cve_id:
            return False
        return bool(cls.CVE_REGEX.match(cve_id))
        
    @classmethod
    def validate_cvss(cls, cvss_score: Optional[float]) -> Optional[float]:
        """Validates CVSS score falls within 0.0 to 10.0 range."""
        if cvss_score is None:
            return None
        if 0.0 <= cvss_score <= 10.0:
            return cvss_score
        logger.warning(f"Invalid CVSS score detected: {cvss_score}. Discarding.")
        return None
        
    @classmethod
    def validate_epss(cls, epss_score: Optional[float]) -> Optional[float]:
        """Validates EPSS score falls within 0.0 to 1.0 range (often represented as 0-100%)."""
        if epss_score is None:
            return None
        # Internally EPSS should be 0.0 to 1.0 or 0 to 100, assuming 0.0 to 100.0 here for safety.
        # But standard EPSS is 0.0 to 1.0
        if 0.0 <= epss_score <= 1.0:
            return epss_score
        logger.warning(f"Invalid EPSS score detected: {epss_score}. Discarding.")
        return None
        
    @classmethod
    def validate_osv_record(cls, record: Dict[str, Any]) -> bool:
        """Validates an OSV source record."""
        # Must have an ID and it should ideally be a valid CVE, though OSV has GHSA, etc.
        # But if it's a CVE, it must be well formed.
        vuln_id = record.get("id", "")
        if not vuln_id:
            return False
            
        if vuln_id.startswith("CVE-") and not cls.validate_cve_format(vuln_id):
            logger.warning(f"Invalid CVE format in OSV record: {vuln_id}")
            return False
            
        # Reject reserved/rejected CVEs if they appear in summary/details
        details = record.get("details", "").lower()
        summary = record.get("summary", "").lower()
        
        if "** rejected **" in details or "** rejected **" in summary:
            return False
        if "** reserved **" in details or "** reserved **" in summary:
            return False
            
        return True

    @classmethod
    def validate_nvd_record(cls, record: Dict[str, Any]) -> bool:
        """Validates an NVD source record.
        
        Rejected CVEs are discarded (return False).
        Reserved CVEs are allowed through but should be tagged for reconciliation.
        """
        # Support both wrapper dictionary {"cve": cve_dict} and direct cve_dict
        cve_data = record.get("cve")
        if cve_data is None or not isinstance(cve_data, dict):
            cve_data = record
            
        cve_id = cve_data.get("id", "")
        if not cve_id or not cls.validate_cve_format(cve_id):
            return False
            
        vuln_status = cve_data.get("vulnStatus", "").lower()
        if vuln_status == "rejected":
            return False
        # Reserved CVEs are allowed through — they'll be tagged with
        # vuln_status="Reserved" and reconciled on future scans
            
        return True
        
    @classmethod
    def deduplicate_findings(cls, findings: List[VulnerabilityFinding]) -> List[VulnerabilityFinding]:
        """Removes duplicate findings based on package name and CVE ID."""
        unique_findings = []
        seen = set()
        
        for f in findings:
            key = (f.package.name, f.cve_id)
            if key not in seen:
                # Also apply bounds validation
                f.cvss_score = cls.validate_cvss(f.cvss_score)
                f.epss_score = cls.validate_epss(f.epss_score)
                
                # Check format
                if f.cve_id.startswith("CVE-") and not cls.validate_cve_format(f.cve_id):
                    logger.warning(f"Discarding malformed CVE finding: {f.cve_id}")
                    continue
                    
                seen.add(key)
                unique_findings.append(f)
                
        return unique_findings


class VersionIntegrityValidator:
    """Enforces version validation checks and registry existence rules."""

    @classmethod
    def validate_metadata(cls, ecosystem: str, metadata: Any, versions: List[str]) -> None:
        """Validates the package VersionMetadata object against a list of registry versions."""
        if not metadata:
            return

        # Registry existence check
        if versions and metadata.current_version not in versions:
            metadata.verification_state = "UNVERIFIED"
            logger.warning(
                "⚠ Version %s for package %s was not found in registry", 
                metadata.current_version, 
                metadata.canonical_name
            )
            
        comparator = get_comparator(ecosystem)
        current = metadata.current_version
        
        # 1. latest_version >= current_version
        if metadata.latest_stable_version:
            try:
                if not comparator.compare(metadata.latest_stable_version, ">=", current):
                    metadata.verification_state = "UNVERIFIED"
                    logger.warning(
                        "Version validation failed: latest_stable_version (%s) < current_version (%s)", 
                        metadata.latest_stable_version, 
                        current
                    )
            except Exception as e:
                logger.debug("Failed comparator check: %s", e)
                metadata.verification_state = "UNVERIFIED"
                
        # 2. minimum_safe_version >= current_version
        if metadata.minimum_safe_version:
            try:
                if not comparator.compare(metadata.minimum_safe_version, ">=", current):
                    metadata.verification_state = "UNVERIFIED"
                    logger.warning(
                        "Version validation failed: minimum_safe_version (%s) < current_version (%s)", 
                        metadata.minimum_safe_version, 
                        current
                    )
            except Exception as e:
                logger.debug("Failed comparator check: %s", e)
                metadata.verification_state = "UNVERIFIED"
                
        # 3. fixed_version <= latest_version
        if metadata.recommendation and metadata.recommendation.minimum_safe_version and metadata.latest_stable_version:
            try:
                if not comparator.compare(metadata.recommendation.minimum_safe_version, "<=", metadata.latest_stable_version):
                    metadata.verification_state = "UNVERIFIED"
                    logger.warning(
                        "Version validation failed: minimum_safe_version (%s) > latest_stable_version (%s)", 
                        metadata.recommendation.minimum_safe_version, 
                        metadata.latest_stable_version
                    )
            except Exception as e:
                logger.debug("Failed comparator check: %s", e)
                metadata.verification_state = "UNVERIFIED"

