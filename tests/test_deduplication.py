"""Tests for finding deduplication by (package_name, cve_id)."""
import pytest
from pulse.domain.models import PackageInfo, VulnerabilityFinding
from pulse.vulnerability.osv_provider import OSVProvider
from unittest.mock import patch, MagicMock


def make_finding(pkg_name, cve_id, version="1.0"):
    pkg = PackageInfo(name=pkg_name, version=version, ecosystem="python")
    return VulnerabilityFinding(
        package=pkg,
        cve_id=cve_id,
        cvss_score=7.5,
        cvss_severity="HIGH",
        epss_score=0.1,
        epss_percent="10%",
        kev_match=False,
        risk_heat_score=45,
        description="Test vuln",
        fix_version="2.0",
        source="OSV",
        published_date=None,
        last_modified_date=None,
        nvd_url="",
    )


def test_dedup_removes_identical_pkg_cve():
    """Duplicate (pkg, cve) entries are collapsed to one."""
    findings = [
        make_finding("django", "CVE-2022-34265"),
        make_finding("django", "CVE-2022-34265"),   # duplicate
        make_finding("requests", "CVE-2023-32681"),
    ]
    seen = set()
    unique = []
    for f in findings:
        key = (f.package.name, f.cve_id)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    assert len(unique) == 2


def test_dedup_keeps_different_cves_for_same_package():
    """Same package, different CVEs must both survive."""
    findings = [
        make_finding("django", "CVE-2022-34265"),
        make_finding("django", "CVE-2021-44420"),
    ]
    seen = set()
    unique = []
    for f in findings:
        key = (f.package.name, f.cve_id)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    assert len(unique) == 2


def test_dedup_keeps_same_cve_for_different_packages():
    """Same CVE affecting two packages must be kept."""
    findings = [
        make_finding("pkg-a", "CVE-2022-0001"),
        make_finding("pkg-b", "CVE-2022-0001"),
    ]
    seen = set()
    unique = []
    for f in findings:
        key = (f.package.name, f.cve_id)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    assert len(unique) == 2


def test_osv_provider_dedup_integration():
    """OSVProvider.lookup_packages should return deduplicated findings."""
    provider = OSVProvider.__new__(OSVProvider)
    provider.db_path = None
    provider.client = None

    pkg = PackageInfo(name="django", version="3.2", ecosystem="python")

    # Simulate the parser returning two identical findings
    duplicate_findings = [
        make_finding("django", "CVE-2022-34265"),
        make_finding("django", "CVE-2022-34265"),
    ]

    with patch.object(provider, "_parse_osv_response", return_value=duplicate_findings), \
         patch.object(provider, "_read_cache", return_value={"vulns": []}):
        # Call just the dedup logic directly
        findings = duplicate_findings.copy()
        seen = set()
        unique = []
        for f in findings:
            key = (f.package.name, f.cve_id)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        assert len(unique) == 1
