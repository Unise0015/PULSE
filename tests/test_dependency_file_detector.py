import pytest
from pathlib import Path
from pulse.parsers.file_detector import DependencyFileDetector, DependencyFileType


class TestDependencyFileDetector:
    """Component 12 & 13 – Unit tests for DependencyFileDetector."""

    def test_python_requirements_filename_patterns(self):
        filenames = [
            "requirements.txt",
            "requirements (1).txt",
            "requirements (2).txt",
            "requirements-dev.txt",
            "requirements_test.txt",
            "requirements-prod.txt",
            "requirements-dev-local.txt",
            "requirements.lock",
            "requirements.in",
        ]
        for fname in filenames:
            file_type = DependencyFileDetector.detect(Path(f"/some/path/{fname}"))
            assert file_type == DependencyFileType.PYTHON_REQUIREMENTS, f"Failed for {fname}"

    def test_npm_filename_patterns(self):
        filenames = [
            "package.json",
            "package (1).json",
            "package-copy.json",
            "package-test.json",
        ]
        for fname in filenames:
            file_type = DependencyFileDetector.detect(Path(f"/some/path/{fname}"))
            assert file_type == DependencyFileType.PACKAGE_JSON, f"Failed for {fname}"

        lock_files = [
            "package-lock.json",
            "package-lock (1).json",
            "package-lock-copy.json",
        ]
        for fname in lock_files:
            file_type = DependencyFileDetector.detect(Path(f"/some/path/{fname}"))
            assert file_type == DependencyFileType.NPM_LOCK, f"Failed for {fname}"

    def test_cargo_filename_patterns(self):
        for fname in ["Cargo.toml", "Cargo (1).toml"]:
            assert DependencyFileDetector.detect(Path(fname)) == DependencyFileType.CARGO_TOML
        for fname in ["Cargo.lock", "Cargo (1).lock"]:
            assert DependencyFileDetector.detect(Path(fname)) == DependencyFileType.CARGO_LOCK

    def test_go_filename_patterns(self):
        for fname in ["go.mod", "go (1).mod"]:
            assert DependencyFileDetector.detect(Path(fname)) == DependencyFileType.GO_MOD
        for fname in ["go.sum", "go (1).sum"]:
            assert DependencyFileDetector.detect(Path(fname)) == DependencyFileType.GO_SUM

    def test_ruby_filename_patterns(self):
        for fname in ["Gemfile", "Gemfile (1)"]:
            assert DependencyFileDetector.detect(Path(fname)) == DependencyFileType.GEMFILE
        for fname in ["Gemfile.lock", "Gemfile.lock (1)", "Gemfile (1).lock"]:
            assert DependencyFileDetector.detect(Path(fname)) == DependencyFileType.GEMFILE_LOCK

    def test_composer_filename_patterns(self):
        for fname in ["composer.json", "composer (1).json"]:
            assert DependencyFileDetector.detect(Path(fname)) == DependencyFileType.COMPOSER_JSON
        for fname in ["composer.lock", "composer (1).lock"]:
            assert DependencyFileDetector.detect(Path(fname)) == DependencyFileType.COMPOSER_LOCK

    def test_maven_filename_patterns(self):
        for fname in ["pom.xml", "pom (1).xml"]:
            assert DependencyFileDetector.detect(Path(fname)) == DependencyFileType.MAVEN_POM

    def test_content_inspection_python_requirements(self, tmp_path):
        random_file = tmp_path / "random.txt"
        random_file.write_text("Django==3.2\nrequests>=2.27.0\nflask\n", encoding="utf-8")

        file_type = DependencyFileDetector.detect(random_file)
        assert file_type == DependencyFileType.PYTHON_REQUIREMENTS

    def test_content_inspection_package_json(self, tmp_path):
        random_file = tmp_path / "random.json"
        random_file.write_text('{\n  "dependencies": {\n    "react": "18.2.0"\n  }\n}', encoding="utf-8")

        file_type = DependencyFileDetector.detect(random_file)
        assert file_type == DependencyFileType.PACKAGE_JSON

    def test_content_inspection_npm_lock(self, tmp_path):
        random_file = tmp_path / "random-lock.json"
        random_file.write_text('{\n  "name": "my-app",\n  "lockfileVersion": 3\n}', encoding="utf-8")

        file_type = DependencyFileDetector.detect(random_file)
        assert file_type == DependencyFileType.NPM_LOCK
