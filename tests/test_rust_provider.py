import pytest
from pathlib import Path
from pulse.ecosystems.rust_provider import RustProvider

def test_rust_provider_detection(tmp_path):
    provider = RustProvider()
    assert not provider.detect(tmp_path)
    
    (tmp_path / "Cargo.toml").write_text("", encoding="utf-8")
    assert provider.detect(tmp_path)

def test_rust_provider_parse_cargo_lock(tmp_path):
    lock_content = """
[[package]]
name = "serde"
version = "1.0.152"
dependencies = [
 "serde_derive",
]

[[package]]
name = "serde_derive"
version = "1.0.152"
"""
    (tmp_path / "Cargo.lock").write_text(lock_content, encoding="utf-8")
    
    provider = RustProvider()
    packages = provider.discover_packages(tmp_path)
    edges = provider.discover_dependency_edges(tmp_path)
    
    assert len(packages) == 2
    names = {pkg.name for pkg in packages}
    assert "serde" in names
    assert "serde_derive" in names
    
    assert len(edges) == 1
    assert edges[0].parent_name == "serde"
    assert edges[0].child_name == "serde_derive"
