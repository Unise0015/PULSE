from typing import List, Optional
from pulse.domain.models import VulnerabilityFinding, VersionMetadata
from pulse.version_intelligence.models import UpgradeRecommendation

def recommend_upgrade(
    package: str,
    ecosystem: str,
    current_version: str,
    findings: List[VulnerabilityFinding],
    version_metadata: Optional[VersionMetadata] = None,
    package_manager: str = ""
) -> UpgradeRecommendation:
    """Computes an evidence-based, release-line aware verified upgrade recommendation using single source of truth."""
    from pulse.version_intelligence.recommendation_engine import analyze_upgrade_recommendation
    return analyze_upgrade_recommendation(
        pkg_name=package,
        ecosystem=ecosystem,
        current_version=current_version,
        findings=findings,
        version_metadata=version_metadata,
        verify_candidate=True
    )
