import pytest
from pathlib import Path
from pulse.ecosystems.ruby_provider import RubyProvider

def test_ruby_provider_detection(tmp_path):
    provider = RubyProvider()
    assert not provider.detect(tmp_path)
    
    (tmp_path / "Gemfile").write_text("", encoding="utf-8")
    assert provider.detect(tmp_path)

def test_ruby_provider_parse_gemfile_lock(tmp_path):
    lock_content = """
GEM
  remote: https://rubygems.org/
  specs:
    activemodel (7.0.4.3)
      activesupport (= 7.0.4.3)
    activesupport (7.0.4.3)

DEPENDENCIES
  activemodel
"""
    (tmp_path / "Gemfile.lock").write_text(lock_content, encoding="utf-8")
    
    provider = RubyProvider()
    packages = provider.discover_packages(tmp_path)
    edges = provider.discover_dependency_edges(tmp_path)
    
    assert len(packages) == 2
    activemodel_pkg = [p for p in packages if p.name == "activemodel"][0]
    activesupport_pkg = [p for p in packages if p.name == "activesupport"][0]
    
    assert activemodel_pkg.version == "7.0.4.3"
    assert activemodel_pkg.dependency_type == "DIRECT"
    assert activesupport_pkg.dependency_type == "TRANSITIVE"
    
    assert len(edges) == 1
    assert edges[0].parent_name == "activemodel"
    assert edges[0].child_name == "activesupport"
