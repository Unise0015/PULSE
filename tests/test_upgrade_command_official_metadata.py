import pytest
from pulse.version_intelligence.command_generator import generate_package_manager_commands
from pulse.version_intelligence.models import UpgradeRecommendation
from pulse.remediation.command_generator import generate_upgrade_command


class TestExactVersionPinning:
    """Verify upgrade commands always use exact version pinning."""

    def test_pip_exact_pin(self):
        commands = generate_package_manager_commands("Django", "6.1", "pypi")
        rec_cmds = [c for c in commands if c.recommended]
        assert len(rec_cmds) == 1
        assert rec_cmds[0].command == "pip install Django==6.1"

    def test_pip_no_range(self):
        commands = generate_package_manager_commands("Django", "6.1", "pypi")
        for cmd in commands:
            if cmd.recommended:
                assert ">=" not in cmd.command
                assert "<" not in cmd.command

    def test_npm_exact_pin(self):
        commands = generate_package_manager_commands("express", "4.19.2", "npm")
        rec_cmds = [c for c in commands if c.recommended]
        assert len(rec_cmds) == 1
        assert rec_cmds[0].command == "npm install express@4.19.2"

    def test_cargo_exact_pin(self):
        commands = generate_package_manager_commands("serde", "1.0.200", "cargo")
        rec_cmds = [c for c in commands if c.recommended]
        assert len(rec_cmds) == 1
        assert rec_cmds[0].command == "cargo add serde@1.0.200"

    def test_composer_exact_pin(self):
        commands = generate_package_manager_commands("vendor/pkg", "2.5.0", "composer")
        rec_cmds = [c for c in commands if c.recommended]
        assert len(rec_cmds) == 1
        assert rec_cmds[0].command == "composer require vendor/pkg:2.5.0"
        assert "^" not in rec_cmds[0].command

    def test_nuget_exact_pin(self):
        commands = generate_package_manager_commands("Newtonsoft.Json", "13.0.3", "nuget")
        rec_cmds = [c for c in commands if c.recommended]
        assert len(rec_cmds) == 1
        assert rec_cmds[0].command == "dotnet add package Newtonsoft.Json --version 13.0.3"

    def test_gem_exact_pin(self):
        commands = generate_package_manager_commands("rails", "7.1.0", "rubygems")
        rec_cmds = [c for c in commands if c.recommended]
        assert len(rec_cmds) == 1
        assert rec_cmds[0].command == "gem install rails -v 7.1.0"


class TestRecommendationUpgradeCommand:
    """Verify UpgradeRecommendation.upgrade_command returns the exact pin."""

    def test_upgrade_command_exact_version(self):
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

        assert rec.upgrade_command == "pip install Django==6.1"
        assert ">=" not in rec.upgrade_command
        assert "<" not in rec.upgrade_command

    def test_upgrade_command_never_targets_rejected_candidate(self):
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

        assert "5.1.14" not in rec.upgrade_command
        assert "6.1" in rec.upgrade_command


class TestRemediationCommandGenerator:
    """Verify the remediation command_generator also uses exact pinning."""

    def test_pip_exact_pin(self):
        cmd = generate_upgrade_command("Django", "pypi", "6.1")
        assert cmd == "pip install Django==6.1"

    def test_npm_exact_pin(self):
        cmd = generate_upgrade_command("express", "npm", "4.19.2")
        assert cmd == "npm install express@4.19.2"

    def test_no_invented_ranges(self):
        cmd = generate_upgrade_command("Django", "pypi", "6.1")
        assert ">=" not in cmd
        assert "<" not in cmd
