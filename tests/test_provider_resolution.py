import pytest
import ast
import os
from pathlib import Path
from pulse.ecosystems.base import ECOSYSTEM_REGISTRY_MAP


class TestProviderDisplayNameAndRegistryName:
    """Tests that all providers expose display_name and registry_name."""

    def test_python_provider_properties(self):
        from pulse.ecosystems.python.plugin import PythonPlugin
        p = PythonPlugin()
        assert p.display_name == "Python"
        assert p.registry_name == "PyPI"
        assert p.manifest.ecosystem == "PyPI"

    def test_node_provider_properties(self):
        from pulse.ecosystems.npm.plugin import NodePlugin
        p = NodePlugin()
        assert p.display_name == "Node.js"
        assert p.registry_name == "npm"
        assert p.manifest.ecosystem == "npm"

    def test_rust_provider_properties(self):
        from pulse.ecosystems.rust.plugin import RustPlugin
        p = RustPlugin()
        assert p.display_name == "Rust"
        assert p.registry_name == "crates.io"

    def test_go_provider_properties(self):
        from pulse.ecosystems.go.plugin import GoPlugin
        p = GoPlugin()
        assert p.display_name == "Go"
        assert p.registry_name == "Go Modules"

    def test_ruby_provider_properties(self):
        from pulse.ecosystems.ruby.plugin import RubyPlugin
        p = RubyPlugin()
        assert p.display_name == "Ruby"
        assert p.registry_name == "RubyGems"

    def test_composer_provider_properties(self):
        from pulse.ecosystems.composer.plugin import ComposerPlugin
        p = ComposerPlugin()
        assert p.display_name == "Composer"
        assert p.registry_name == "Packagist"

    def test_nuget_provider_properties(self):
        from pulse.ecosystems.nuget.plugin import NuGetPlugin
        p = NuGetPlugin()
        assert p.display_name == "NuGet"
        assert p.registry_name == "NuGet"

    def test_maven_provider_properties(self):
        from pulse.ecosystems.maven.plugin import MavenPlugin
        p = MavenPlugin()
        assert p.display_name == "Maven"
        assert p.registry_name == "Maven Central"


class TestNoEcosystemNameInCLI:
    """Verify that cli.py no longer references ecosystem_name for provider lookup."""

    def test_cli_has_no_ecosystem_name_provider_lookup(self):
        cli_path = Path(__file__).resolve().parent.parent / "src" / "pulse" / "cli.py"
        source = cli_path.read_text(encoding="utf-8")
        tree = ast.parse(source)

        # Walk AST looking for attribute accesses on .ecosystem_name
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                if node.attr == "ecosystem_name":
                    pytest.fail(
                        f"cli.py still references '.ecosystem_name' at line {node.lineno}. "
                        f"Use display_name or registry_name instead."
                    )


class TestNoSecondaryProviderLookup:
    """Verify no `next(... ecosystem_name ...)` pattern exists in cli.py."""

    def test_no_next_provider_lookup_in_cli(self):
        cli_path = Path(__file__).resolve().parent.parent / "src" / "pulse" / "cli.py"
        source = cli_path.read_text(encoding="utf-8")

        # Check for the old pattern: next((p for p in registry... if p.ecosystem_name
        assert "p.ecosystem_name == ecosystem" not in source, \
            "cli.py still contains the old 'next(... ecosystem_name ...)' provider lookup pattern"

    def test_no_ecosystem_name_in_scan_single_package(self):
        cli_path = Path(__file__).resolve().parent.parent / "src" / "pulse" / "cli.py"
        source = cli_path.read_text(encoding="utf-8")

        # Find the scan_single_package_menu function body
        lines = source.splitlines()
        in_function = False
        for i, line in enumerate(lines, 1):
            if "def scan_single_package_menu" in line:
                in_function = True
                continue
            if in_function and line.startswith("def ") and "scan_single_package_menu" not in line:
                break
            if in_function and "ecosystem_name" in line:
                pytest.fail(
                    f"scan_single_package_menu still references 'ecosystem_name' at line {i}: {line.strip()}"
                )
