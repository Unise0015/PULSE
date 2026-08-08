import pytest
from pathlib import Path
from pulse.ecosystems.base import EcosystemRegistry, EcosystemProvider
from pulse.domain.models import PackageInfo, DependencyEdge

class DummyProvider(EcosystemProvider):
    def __init__(self, name, osv, file_to_detect):
        self._name = name
        self._osv = osv
        self._file = file_to_detect

    @property
    def ecosystem_name(self) -> str:
        return self._name

    @property
    def osv_ecosystem(self) -> str:
        return self._osv

    def detect(self, path: Path) -> bool:
        return (path / self._file).exists()

    def discover_packages(self, path: Path) -> list[PackageInfo]:
        return [PackageInfo(name="dummy", version="1.0.0", ecosystem=self._osv)]

    def discover_dependency_edges(self, path: Path) -> list[DependencyEdge]:
        return []

def test_registry_registration_and_detection(tmp_path):
    registry = EcosystemRegistry()
    registry.reset()
    try:
        provider1 = DummyProvider("Rust", "crates.io", "Cargo.lock")
        provider2 = DummyProvider("Go", "Go", "go.mod")

        registry.register(provider1)
        registry.register(provider2)

        # Detect with empty path
        assert len(registry.detect(tmp_path)) == 0

        # Create Cargo.lock
        (tmp_path / "Cargo.lock").write_text("", encoding="utf-8")
        detected = registry.detect(tmp_path)
        assert len(detected) == 1
        assert detected[0].display_name == "Rust"

        # Create go.mod
        (tmp_path / "go.mod").write_text("", encoding="utf-8")
        detected2 = registry.detect(tmp_path)
        assert len(detected2) == 2
    finally:
        registry.reset()
