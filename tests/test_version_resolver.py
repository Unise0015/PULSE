import pytest
from pulse.domain.models import PackageInfo, VulnerabilityFinding, VersionMetadata
from pulse.remediation.version_resolver import VersionResolver


def test_prerelease_detection():
    assert VersionResolver.is_prerelease("2.0.0-alpha") is True
    assert VersionResolver.is_prerelease("1.9.0-rc1") is True
    assert VersionResolver.is_prerelease("4.2.26") is False


def test_latest_stable_vs_available():
    fix_versions = ["2.0.0-rc1", "1.9.8", "1.9.5"]
    meta = VersionMetadata(
        current_version="1.9.0",
        latest_stable_version="1.9.8",
        latest_security_fix="1.9.8",
        minimum_safe_version="1.9.5",
        latest_lts_version="1.9.8",
        canonical_name="demo",
        display_name="demo",
        source_registry="PyPI",
        source_confidence="authoritative",
        registry_available=True,
        verification_state="VERIFIED",
        branch_status="SUPPORTED",
        source_timestamp=None
    )
    stable, avail = VersionResolver.get_latest_versions("1.9.0", fix_versions, meta)
    assert avail == "2.0.0-rc1"
    assert stable == "1.9.8"


def test_lts_branch_detection():
    assert VersionResolver.is_lts_branch("django", "4.2.26") is True
    assert VersionResolver.is_lts_branch("node", "20.11.0") is True
    assert VersionResolver.is_lts_branch("express", "4.16.0") is False
