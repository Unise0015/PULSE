import pytest
from pathlib import Path
from pulse.ecosystems.python_provider import PythonProvider

def test_python_provider_detection(tmp_path):
    provider = PythonProvider()
    (tmp_path / "requirements.txt").write_text("", encoding="utf-8")
    assert provider.detect(tmp_path)

def test_python_provider_parse_requirements(tmp_path):
    req_content = """
requests==2.28.1
django>=3.2 # Web Framework
flask
"""
    (tmp_path / "requirements.txt").write_text(req_content, encoding="utf-8")
    
    provider = PythonProvider()
    packages = provider.discover_packages(tmp_path)
    edges = provider.discover_dependency_edges(tmp_path)
    
    assert len(packages) == 3
    names = {pkg.name for pkg in packages}
    assert "requests" in names
    assert "django" in names
    assert "flask" in names
    
    # Flat requirements has no edges
    assert len(edges) == 0
