import pytest
import json
from pathlib import Path
from pulse.ecosystems.node_provider import NodeProvider

def test_node_provider_detection(tmp_path):
    provider = NodeProvider()
    assert not provider.detect(tmp_path)
    
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    assert provider.detect(tmp_path)

def test_node_provider_parse_lockfile(tmp_path):
    lock_data = {
        "name": "test-project",
        "packages": {
            "": {
                "dependencies": {
                    "react": "^17.0.2"
                }
            },
            "node_modules/react": {
                "version": "17.0.2",
                "dependencies": {
                    "object-assign": "^4.1.1"
                }
            },
            "node_modules/object-assign": {
                "version": "4.1.1"
            }
        }
    }
    
    (tmp_path / "package-lock.json").write_text(json.dumps(lock_data), encoding="utf-8")
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"react": "^17.0.2"}}), encoding="utf-8")
    
    provider = NodeProvider()
    packages = provider.discover_packages(tmp_path)
    edges = provider.discover_dependency_edges(tmp_path)
    
    assert len(packages) == 2
    react_pkg = [p for p in packages if p.name == "react"][0]
    assert react_pkg.version == "17.0.2"
    assert react_pkg.dependency_type == "DIRECT"
    
    object_pkg = [p for p in packages if p.name == "object-assign"][0]
    assert object_pkg.version == "4.1.1"
    assert object_pkg.dependency_type == "TRANSITIVE"
    
    assert len(edges) == 1
    assert edges[0].parent_name == "react"
    assert edges[0].child_name == "object-assign"
