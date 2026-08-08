import pytest
import sqlite3
import json
import threading
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

from pulse.domain.models import PackageInfo, VulnerabilityFinding, VersionMetadata
from pulse.domain.version import (
    BranchStatus,
    RegistryType,
    NormalizedAffectedRange,
    get_comparator,
    PyPIComparator,
    NpmComparator,
    GenericComparator
)
from pulse.domain.data_validation import VersionIntegrityValidator
from pulse.vulnerability.version_intelligence import VersionIntelligenceService
from pulse.security_advisor import SecurityAdvisor


# ── 1. Comparator Tests ───────────────────────────────────────────────────────

class TestVersionComparators:
    def test_pypi_comparator(self):
        comp = get_comparator("PyPI")
        assert isinstance(comp, PyPIComparator)
        assert comp.is_stable("1.2.3") is True
        assert comp.is_stable("1.2.3a1") is False
        assert comp.is_stable("1.2.3rc2") is False
        
        # Test comparisons
        assert comp.compare("1.2.3", ">=", "1.2.0") is True
        assert comp.compare("1.2.3a1", "<", "1.2.3") is True
        # Normalization test (.RELEASE and .Final should be stripped)
        assert comp.compare("1.0.0.RELEASE", "==", "1.0.0") is True
        assert comp.compare("1.0.0.Final", "==", "1.0.0") is True
        
    def test_npm_comparator(self):
        comp = get_comparator("npm")
        assert isinstance(comp, NpmComparator)
        assert comp.is_stable("1.2.3") is True
        assert comp.is_stable("1.2.3-beta.1") is False
        
        # SemVer rules
        assert comp.compare("1.2.3-alpha.1", "<", "1.2.3-beta.2") is True
        assert comp.compare("1.2.3-rc.1", "<", "1.2.3") is True
        assert comp.compare("1.0.0-rc.1+build.1", "==", "1.0.0-rc.1") is True

    def test_generic_comparator(self):
        comp = get_comparator("crates.io")
        assert isinstance(comp, GenericComparator)
        assert comp.is_stable("1.2.3") is True
        assert comp.is_stable("1.2.3-alpha") is False
        
        # Standard comparisons
        assert comp.compare("1.2.3-alpha", "<", "1.2.3") is True
        assert comp.compare("2.0.0", ">", "1.9.9") is True


# ── 2. EOL Branch Policies Tests ──────────────────────────────────────────────

def test_eol_branch_status():
    service = VersionIntelligenceService()
    # django==3.2 EOL
    assert service.check_branch_status("django", "3.2") == BranchStatus.EOL
    assert service.check_branch_status("django", "3.2.25") == BranchStatus.EOL
    # django==4.2 Supported
    assert service.check_branch_status("django", "4.2.0") == BranchStatus.SUPPORTED
    # Unknown package
    assert service.check_branch_status("nonexistent-pkg", "1.0.0") == BranchStatus.UNKNOWN


# ── 3. Database Cache & Diagnostics Tests ──────────────────────────────────────

@pytest.fixture
def temp_db_service(tmp_path):
    db_file = tmp_path / "test_version_cache.db"
    
    # Initialize the package_version_cache table
    with sqlite3.connect(db_file) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS package_version_cache (
                ecosystem        TEXT,
                package_name     TEXT,
                versions_json    TEXT,
                latest_stable    TEXT,
                latest_lts       TEXT,
                registry_payload TEXT,
                schema_version   INTEGER DEFAULT 1,
                cache_hits       INTEGER DEFAULT 0,
                cache_misses     INTEGER DEFAULT 0,
                last_error       TEXT,
                last_success     DATETIME,
                updated_at       DATETIME DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY(ecosystem, package_name)
            )
        """)
        conn.commit()

    with patch("pulse.vulnerability.version_intelligence.get_db_path", return_value=db_file):
        service = VersionIntelligenceService()
        yield service


def test_cache_hits_and_misses(temp_db_service):
    # Miss first
    res = temp_db_service._read_cache("pypi", "django")
    assert res is None
    
    # Write cache
    data = {
        "versions": ["3.2", "4.2", "5.2.0"],
        "latest_stable": "5.2.0",
        "latest_lts": "4.2.1",
        "raw_payload": {}
    }
    temp_db_service._write_cache("pypi", "django", data)
    
    # Check hits increment
    cached_res = temp_db_service._read_cache("pypi", "django")
    assert cached_res is not None
    assert cached_res["latest_stable"] == "5.2.0"
    assert cached_res["cache_hits"] == 1
    
    cached_res_2 = temp_db_service._read_cache("pypi", "django")
    assert cached_res_2["cache_hits"] == 2


# ── 4. Asynchronous Cache Refreshing Tests ────────────────────────────────────

def test_async_refresh_triggered_on_warm_cache(temp_db_service):
    # Setup cache entry that is 13 hours old (warm, trigger refresh)
    warm_time = (datetime.now() - timedelta(hours=13)).strftime("%Y-%m-%d %H:%M:%S")
    with sqlite3.connect(temp_db_service.db_path) as conn:
        conn.execute("""
            INSERT INTO package_version_cache (
                ecosystem, package_name, versions_json, latest_stable, latest_lts, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?)
        """, ("pypi", "django", json.dumps(["3.2", "4.2"]), "4.2", "3.2", warm_time))
        conn.commit()

    with patch("threading.Thread") as mock_thread:
        res = temp_db_service.fetch_version_data("pypi", "django", offline=False)
        assert res["versions"] == ["3.2", "4.2"]
        mock_thread.assert_called_once()


# ── 5. Offline Fallback & Network Failures Tests ──────────────────────────────

def test_offline_mode_behavior(temp_db_service):
    # Scanned offline without cache
    res = temp_db_service.fetch_version_data("pypi", "django", offline=True)
    assert res["versions"] == []
    assert res["verification_state"] == "UNKNOWN"
    
    # Cache a stale entry (8 days old)
    stale_time = (datetime.now() - timedelta(days=8)).strftime("%Y-%m-%d %H:%M:%S")
    with sqlite3.connect(temp_db_service.db_path) as conn:
        conn.execute("""
            REPLACE INTO package_version_cache (
                ecosystem, package_name, versions_json, latest_stable, updated_at
            ) VALUES (?, ?, ?, ?, ?)
        """, ("pypi", "django", json.dumps(["3.2", "4.2"]), "4.2", stale_time))
        conn.commit()

    # Should fall back to cached entry but label as STALE
    res2 = temp_db_service.fetch_version_data("pypi", "django", offline=True)
    assert res2["versions"] == ["3.2", "4.2"]
    assert res2["verification_state"] == "STALE"


# ── 6. Concurrency Check ──────────────────────────────────────────────────────

def test_concurrent_enrichment(temp_db_service):
    # Mock PyPIClient and NpmClient to return values instantly
    mock_client = MagicMock()
    mock_client.fetch_metadata.return_value = {
        "versions": ["1.0.0", "1.1.0"],
        "latest_stable": "1.1.0",
        "latest_lts": None,
        "display_name": "mock-pkg",
        "raw_payload": {}
    }
    
    pkgs = [
        PackageInfo(name=f"pkg-{i}", version="1.0.0", ecosystem="PyPI")
        for i in range(5)
    ]
    
    with patch("pulse.vulnerability.version_intelligence.get_registry_client", return_value=mock_client):
        temp_db_service.enrich_packages(pkgs)
        
    for pkg in pkgs:
        assert pkg.version_metadata is not None
        assert pkg.latest_version == "1.1.0"
        assert pkg.version_metadata.verification_state == "VERIFIED"


# ── 7. Version Integrity Validator Rules ──────────────────────────────────────

class TestVersionIntegrityValidator:
    def test_validate_metadata_success(self):
        # Setup clean version metadata
        meta = VersionMetadata(
            current_version="1.0.0",
            latest_stable_version="1.5.0",
            latest_security_fix=None,
            minimum_safe_version="1.0.0",
            latest_lts_version=None,
            canonical_name="test-pkg",
            display_name="test-pkg",
            source_registry=RegistryType.PYPI,
            source_confidence="authoritative",
            registry_available=True,
            verification_state="VERIFIED",
            branch_status=BranchStatus.SUPPORTED,
            source_timestamp=datetime.now()
        )
        
        # Valid: current exists, latest >= current, minimum_safe >= current
        VersionIntegrityValidator.validate_metadata("pypi", meta, ["1.0.0", "1.1.0", "1.5.0"])
        assert meta.verification_state == "VERIFIED"

    def test_validate_metadata_failures(self):
        # Current version missing in registry
        meta = VersionMetadata(
            current_version="9.9.9",
            latest_stable_version="1.5.0",
            latest_security_fix=None,
            minimum_safe_version="1.0.0",
            latest_lts_version=None,
            canonical_name="test-pkg",
            display_name="test-pkg",
            source_registry=RegistryType.PYPI,
            source_confidence="authoritative",
            registry_available=True,
            verification_state="VERIFIED",
            branch_status=BranchStatus.SUPPORTED,
            source_timestamp=datetime.now()
        )
        VersionIntegrityValidator.validate_metadata("pypi", meta, ["1.0.0", "1.1.0"])
        assert meta.verification_state == "UNVERIFIED"

        # Latest version < current version
        meta2 = VersionMetadata(
            current_version="2.0.0",
            latest_stable_version="1.5.0",
            latest_security_fix=None,
            minimum_safe_version="2.0.0",
            latest_lts_version=None,
            canonical_name="test-pkg",
            display_name="test-pkg",
            source_registry=RegistryType.PYPI,
            source_confidence="authoritative",
            registry_available=True,
            verification_state="VERIFIED",
            branch_status=BranchStatus.SUPPORTED,
            source_timestamp=datetime.now()
        )
        VersionIntegrityValidator.validate_metadata("pypi", meta2, ["2.0.0", "1.5.0"])
        assert meta2.verification_state == "UNVERIFIED"


# ── 8. Django Regression Test (Critical Milestone Requirement) ───────────────

def test_django_3_2_regression_scenario(temp_db_service):
    # Setup django scanned package
    pkg = PackageInfo(name="django", version="3.2", ecosystem="pypi")
    
    # Mock registry returns EOL Django releases
    django_versions = ["3.2", "3.2.1", "3.2.24", "3.2.25", "4.2", "4.2.15", "5.2.0"]
    mock_client = MagicMock()
    mock_client.fetch_metadata.return_value = {
        "versions": django_versions,
        "latest_stable": "5.2.0",
        "latest_lts": "4.2.15",
        "display_name": "Django",
        "raw_payload": {}
    }
    
    with patch("pulse.vulnerability.version_intelligence.get_registry_client", return_value=mock_client):
        temp_db_service.enrich_packages([pkg])
        
    # Verify metadata fields immediately after registry enrichment
    meta = pkg.version_metadata
    assert meta is not None
    assert meta.current_version == "3.2"
    assert meta.latest_stable_version == "5.2.0"
    assert meta.branch_status == BranchStatus.EOL
    
    # Vulnerability Finding: CVE-2024-38875 affecting < 3.2.25
    finding = VulnerabilityFinding(
        package=pkg,
        cve_id="CVE-2024-38875",
        cvss_score=7.5,
        cvss_severity="HIGH",
        epss_score=0.1,
        epss_percent="10%",
        kev_match=False,
        risk_heat_score=45,
        description="Vulnerability affecting django < 3.2.25",
        fix_version="3.2.25",
        source="OSV",
        published_date=None,
        last_modified_date=None,
        nvd_url="",
        affected_ranges=[
            NormalizedAffectedRange(introduced="0", fixed="3.2.25")
        ]
    )
    
    # Evaluate security fix recommendations
    rec = temp_db_service.get_security_fix_version(pkg, pkg.version, [finding])
    
    assert rec is not None
    # Django==3.2.25 is expected minimum safe (remediates <3.2.25 within 3.2 branch)
    assert rec.minimum_safe_version == "3.2.25"
    assert rec.latest_security_fix == "3.2.25"
    assert rec.latest_stable_version == "5.2.0"
    
    # Rationale must recommend upgrading to 3.2.25 within the same-minor branch
    assert "Upgrade within same-minor branch to 3.2.25" in rec.rationale
