import pytest
from pathlib import Path
from pulse.discoverers.file_parser import parse_file
from pulse.parsers.file_detector import DependencyFileDetector, DependencyFileType
from pulse.parsers.registry import ParserRegistry


class TestScanFromFileIntegration:
    """Component 14 & 15 – Integration tests for renamed dependency files."""

    def test_renamed_python_requirements_parsing(self, tmp_path):
        renamed_file = tmp_path / "requirements (1).txt"
        renamed_file.write_text("Django==3.2\nrequests==2.27.0\n", encoding="utf-8")

        # 1. Detection
        file_type = DependencyFileDetector.detect(renamed_file)
        assert file_type == DependencyFileType.PYTHON_REQUIREMENTS

        # 2. Parsing via parse_file
        packages = parse_file(str(renamed_file))
        assert len(packages) == 2
        pkg_names = {p.name for p in packages}
        assert "Django" in pkg_names
        assert "requests" in pkg_names

    def test_renamed_file_with_quotes(self, tmp_path):
        renamed_file = tmp_path / "requirements (2).txt"
        renamed_file.write_text("flask==2.0.1\n", encoding="utf-8")

        from pulse.utils import normalize_user_path
        quoted_path = f'"{renamed_file}"'
        clean_path = normalize_user_path(quoted_path)

        packages = parse_file(clean_path)
        assert len(packages) == 1
        assert packages[0].name == "flask"
        assert packages[0].version == "2.0.1"

    def test_renamed_package_json_parsing(self, tmp_path):
        renamed_file = tmp_path / "package (1).json"
        renamed_file.write_text('{\n  "dependencies": {\n    "express": "4.17.1"\n  }\n}', encoding="utf-8")

        file_type = DependencyFileDetector.detect(renamed_file)
        assert file_type == DependencyFileType.PACKAGE_JSON

        packages = parse_file(str(renamed_file))
        assert len(packages) == 1
        assert packages[0].name == "express"
        assert packages[0].version == "4.17.1"
