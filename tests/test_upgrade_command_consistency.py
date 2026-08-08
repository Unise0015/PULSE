import pytest
from pulse.version_intelligence.command_generator import generate_package_manager_commands
from pulse.version_intelligence.recommendation_engine import analyze_upgrade_recommendation
from pulse.domain.models import VulnerabilityFinding, PackageInfo

def test_upgrade_command_generation_uses_exact_pin():
    """The recommended command must use exact version pinning, not a range."""
    commands = generate_package_manager_commands("Django", "6.1", "pypi")
    assert len(commands) > 0
    rec_cmds = [c for c in commands if c.recommended]
    assert len(rec_cmds) == 1
    assert rec_cmds[0].command == "pip install Django==6.1"
    assert ">=" not in rec_cmds[0].command
    assert "<" not in rec_cmds[0].command

def test_recommendation_upgrade_command_matches_recommended_version():
    pkg = PackageInfo(name="Django", version="3.2", ecosystem="pypi")
    finding = VulnerabilityFinding(
        cve_id="CVE-2021-45452",
        package=pkg,
        cvss_score=8.5,
        cvss_severity="HIGH",
        fix_version="5.1.14",
        source="OSV"
    )

    rec = analyze_upgrade_recommendation(
        pkg_name="Django",
        ecosystem="pypi",
        current_version="3.2",
        findings=[finding],
        verify_candidate=False
    )
    # rec.upgrade_command must target recommended_version with exact pin
    assert rec.recommended_version in rec.upgrade_command
    assert "==" in rec.upgrade_command
    assert ">=" not in rec.upgrade_command
