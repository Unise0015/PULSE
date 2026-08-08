from typing import List, Optional
from pulse.domain.models import PackageInfo, VulnerabilityFinding, SecurityFixRecommendation
from pulse.website.technology_catalog import TECHNOLOGY_CATALOG

def get_upgrade_recommendation(tech_key: str, current_version: Optional[str], findings: List[VulnerabilityFinding]) -> Optional[SecurityFixRecommendation]:
    """Generates remediation advice for a website technology.
    
    Args:
        tech_key: Normalized catalog key
        current_version: Current version of technology
        findings: Vulnerability findings matching this technology
        
    Returns:
        SecurityFixRecommendation or None
    """
    if not current_version:
        return None
        
    tech = TECHNOLOGY_CATALOG.get(tech_key.lower())
    if not tech:
        return None
        
    # Fallback/Default recommendation: inspect findings for the highest fix_version
    fix_versions = []
    for f in findings:
        if f.fix_version:
            fix_versions.append(f.fix_version)
            
    if fix_versions:
        try:
            from packaging.version import Version
            parsed_versions = []
            for v in fix_versions:
                try:
                    parsed_versions.append((Version(v), v))
                except Exception:
                    pass
            if parsed_versions:
                parsed_versions.sort()
                highest_fix = parsed_versions[-1][1]
            else:
                fix_versions.sort()
                highest_fix = fix_versions[-1]
        except Exception:
            fix_versions.sort()
            highest_fix = fix_versions[-1]
            
        return SecurityFixRecommendation(
            minimum_safe_version=highest_fix,
            latest_security_fix=highest_fix,
            latest_stable_version=highest_fix,
            rationale=f"Upgrade to version {highest_fix} or higher to resolve vulnerability findings."
        )
        
    # If no fix versions are found, suggest a generic update
    display_name = tech.get("display_name", tech_key)
    return SecurityFixRecommendation(
        minimum_safe_version=None,
        latest_security_fix=None,
        latest_stable_version=None,
        rationale=f"No specific fix version identified. Refer to security advisories for {display_name} upgrade paths."
    )

