import pytest
import json
from pathlib import Path
from pulse.ecosystems.composer_provider import ComposerProvider

def test_composer_provider_detection(tmp_path):
    provider = ComposerProvider()
    assert not provider.detect(tmp_path)
    
    (tmp_path / "composer.json").write_text("{}", encoding="utf-8")
    assert provider.detect(tmp_path)

def test_composer_provider_parse_composer_lock(tmp_path):
    lock_data = {
        "packages": [
            {
                "name": "monolog/monolog",
                "version": "v2.2.0",
                "require": {
                    "psr/log": "^1.0"
                }
            }
        ],
        "packages-dev": []
    }
    
    (tmp_path / "composer.lock").write_text(json.dumps(lock_data), encoding="utf-8")
    (tmp_path / "composer.json").write_text(json.dumps({"require": {"monolog/monolog": "^2.2"}}), encoding="utf-8")
    
    provider = ComposerProvider()
    packages = provider.discover_packages(tmp_path)
    edges = provider.discover_dependency_edges(tmp_path)
    
    assert len(packages) == 1
    assert packages[0].name == "monolog/monolog"
    assert packages[0].version == "2.2.0"
    assert packages[0].dependency_type == "DIRECT"
    
    assert len(edges) == 1
    assert edges[0].parent_name == "monolog/monolog"
    assert edges[0].child_name == "psr/log"
