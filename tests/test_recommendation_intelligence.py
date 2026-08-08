import os
import tempfile
import shutil
from pathlib import Path
from datetime import datetime, timedelta

from pulse.domain.models import PackageInfo, VulnerabilityFinding, VersionMetadata
from pulse.domain.version import RegistryType, BranchStatus
from pulse.version_intelligence import (
    analyze_upgrade_recommendation,
    generate_package_manager_commands,
    UpgradeRecommendation,
    RecommendationStrategy,
    RecommendationConfidence,
    MigrationRisk,
    PackageManager
)
from pulse.history import HistoryService

def test_package_manager_command_generation():
    # Python
    pip_cmds = generate_package_manager_commands("django", "4.2.26", "pypi")
    managers = [c.manager for c in pip_cmds]
    assert PackageManager.PIP in managers
    assert PackageManager.POETRY in managers
    assert PackageManager.UV in managers
    assert any("pip install django==4.2.26" in c.command for c in pip_cmds)

    # Node
    npm_cmds = generate_package_manager_commands("express", "4.19.2", "npm")
    managers_npm = [c.manager for c in npm_cmds]
    assert PackageManager.NPM in managers_npm
    assert PackageManager.PNPM in managers_npm
    assert PackageManager.YARN in managers_npm
    assert any("npm install express@4.19.2" in c.command for c in npm_cmds)

    # Rust
    cargo_cmds = generate_package_manager_commands("tokio", "1.38.0", "cargo")
    assert any("cargo add tokio@1.38.0" in c.command for c in cargo_cmds)

    # PHP
    composer_cmds = generate_package_manager_commands("guzzlehttp/guzzle", "7.8.1", "composer")
    assert any("composer require guzzlehttp/guzzle:7.8.1" in c.command for c in composer_cmds)

    # .NET
    dotnet_cmds = generate_package_manager_commands("Newtonsoft.Json", "13.0.3", "nuget")
    assert any("dotnet add package Newtonsoft.Json --version 13.0.3" in c.command for c in dotnet_cmds)


def test_upgrade_recommendation_analysis():
    pkg = PackageInfo(name="django", version="3.2.0", ecosystem="pypi")
    finding1 = VulnerabilityFinding(
        package=pkg,
        cve_id="CVE-2023-1234",
        cvss_score=8.5,
        cvss_severity="HIGH",
        epss_score=0.2,
        epss_percent="20%",
        kev_match=False,
        risk_heat_score=80,
        description="High risk flaw",
        fix_version="3.2.20",
        source="OSV",
        published_date="2023-01-01",
        last_modified_date="2023-01-02",
        nvd_url="https://nvd.nist.gov/vuln/detail/CVE-2023-1234"
    )
    finding2 = VulnerabilityFinding(
        package=pkg,
        cve_id="CVE-2024-5678",
        cvss_score=9.1,
        cvss_severity="CRITICAL",
        epss_score=0.5,
        epss_percent="50%",
        kev_match=True,
        risk_heat_score=95,
        description="Critical flaw",
        fix_version="4.2.26",
        source="OSV",
        published_date="2024-01-01",
        last_modified_date="2024-01-02",
        nvd_url="https://nvd.nist.gov/vuln/detail/CVE-2024-5678"
    )

    v_meta = VersionMetadata(
        current_version="3.2.0",
        latest_stable_version="6.0.7",
        latest_security_fix="3.2.20",
        minimum_safe_version="4.2.26",
        latest_lts_version="5.0.0",
        canonical_name="django",
        display_name="Django",
        source_registry=RegistryType.PYPI,
        source_confidence="authoritative",
        registry_available=True,
        verification_state="VERIFIED",
        branch_status=BranchStatus.SUPPORTED,
        source_timestamp=datetime.now()
    )

    rec = analyze_upgrade_recommendation(
        pkg_name="django",
        ecosystem="pypi",
        current_version="3.2.0",
        findings=[finding1, finding2],
        version_metadata=v_meta
    )

    assert isinstance(rec, UpgradeRecommendation)
    assert rec.minimum_known_safe == "4.2.26"
    assert rec.latest_stable == "6.0.7"
    assert rec.recommended_version == "4.2.26"
    assert rec.strategy == RecommendationStrategy.MINIMUM_SAFE
    assert rec.alternative_version == "6.0.7"
    assert rec.confidence == RecommendationConfidence.HIGH
    assert rec.migration_risk == MigrationRisk.MEDIUM
    assert any(v.verified for v in rec.verifications if v.source == "Registry Metadata")
    assert len(rec.commands) > 0


def test_history_atomic_asset_purging():
    temp_dir = tempfile.mkdtemp()
    try:
        db_file = os.path.join(temp_dir, "test_history.db")
        history = HistoryService()
        history.db_path = db_file

        from pulse.history.db import init_db
        init_db(Path(db_file))

        # Create dummy report folders
        report1 = Path(temp_dir) / "scan_000001"
        report2 = Path(temp_dir) / "scan_000002"
        report1.mkdir()
        report2.mkdir()
        (report1 / "report.html").write_text("test1")
        (report2 / "report.html").write_text("test2")

        from pulse.domain.models import ScanResult
        scan1 = ScanResult(
            timestamp=datetime.now(),
            hostname="test-host",
            tool_version="4.0.0",
            attack_surface_score=10,
            scan_duration_seconds=1.0,
            target_type="package",
            target_id="test-pkg-1",
            packages_scanned=1,
            findings=[]
        )
        scan2 = ScanResult(
            timestamp=datetime.now(),
            hostname="test-host",
            tool_version="4.0.0",
            attack_surface_score=20,
            scan_duration_seconds=1.5,
            target_type="package",
            target_id="test-pkg-2",
            packages_scanned=2,
            findings=[]
        )

        sid1 = history.save_scan(scan1, report_dir=str(report1))
        sid2 = history.save_scan(scan2, report_dir=str(report2))

        stats_before = history.get_storage_stats()
        assert stats_before["stored_scans_count"] >= 2

        # Purge all history
        deleted = history.clear_history_all()
        assert deleted >= 2
        assert not report1.exists()
        assert not report2.exists()

        stats_after = history.get_storage_stats()
        assert stats_after["stored_scans_count"] == 0
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
