import pytest
from pulse.version_intelligence.models import UpgradeRecommendation

def test_rejected_candidates_not_used_for_upgrade_command():
    rec = UpgradeRecommendation(
        package_name="Django",
        ecosystem="pypi",
        current_version="3.2",
        minimum_known_safe="5.1.14",
        latest_stable="6.1",
        recommended_version="6.1",
        rejected_candidates=["5.1.14"],
        verified_safe=True
    )

    assert rec.recommended_version == "6.1"
    assert "5.1.14" in rec.rejected_candidates
    assert "5.1.14" not in rec.upgrade_command
    assert "6.1" in rec.upgrade_command
