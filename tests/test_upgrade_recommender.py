import pytest
from pulse.domain.models import PackageInfo, VulnerabilityFinding
from pulse.remediation import (
    recommend_upgrade,
    MigrationRisk,
    RecommendationConfidence,
)


def test_django_lts_recommendation():
    pkg = PackageInfo(name="django", version="3.2.0", ecosystem="python")
    f1 = VulnerabilityFinding(package=pkg, cve_id="CVE-2023-0001", fix_version="4.2.26", source="OSV")
    f2 = VulnerabilityFinding(package=pkg, cve_id="CVE-2023-0002", fix_version="6.0.7", source="NVD")

    rec = recommend_upgrade("django", "python", "3.2.0", [f1, f2])

    assert rec.recommended_version == "6.0.7"
    assert rec.migration_risk in (MigrationRisk.MEDIUM, MigrationRisk.HIGH)
    assert "6.0.7" in rec.upgrade_command


def test_requests_patch_recommendation():
    pkg = PackageInfo(name="requests", version="2.27.0", ecosystem="python")
    f = VulnerabilityFinding(package=pkg, cve_id="CVE-2023-32681", fix_version="2.31.0", source="OSV")

    rec = recommend_upgrade("requests", "python", "2.27.0", [f])

    assert rec.recommended_version == "2.31.0"
    assert rec.migration_risk == MigrationRisk.LOW
    assert "2.31.0" in rec.upgrade_command


def test_unknown_fix_version_fallback():
    pkg = PackageInfo(name="demo-pkg", version="1.0.0", ecosystem="npm")
    f = VulnerabilityFinding(package=pkg, cve_id="CVE-2024-9999", fix_version=None, source="OSV")

    rec = recommend_upgrade("demo-pkg", "npm", "1.0.0", [f])

    assert rec.recommended_version is None
    assert rec.recommendation_reason is not None
