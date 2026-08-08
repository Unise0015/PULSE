from pathlib import Path
from typing import List
from pulse.domain.models import PackageInfo
from pulse.parsers.file_detector import DependencyFileDetector, DependencyFileType
from pulse.parsers.registry import ParserRegistry


def parse_file(file_path: str) -> List[PackageInfo]:
    """Parse a supported package manager file using DependencyFileDetector and ParserRegistry."""
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    if not path.is_file():
        raise ValueError(f"Path is not a file: {file_path}")

    file_type = DependencyFileDetector.detect(path)
    if file_type == DependencyFileType.UNKNOWN:
        raise ValueError(
            f"Unable to determine dependency file type for '{path.name}'.\n"
            "Supported dependency formats: Python requirements, package.json, package-lock.json, "
            "Cargo.toml, Cargo.lock, go.mod, go.sum, Gemfile, Gemfile.lock, composer.json, composer.lock, pom.xml"
        )

    return ParserRegistry.parse(path, file_type)
