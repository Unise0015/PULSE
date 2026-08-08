import pytest
from pathlib import Path
from pulse.ecosystems.go_provider import GoProvider

def test_go_provider_detection(tmp_path):
    provider = GoProvider()
    assert not provider.detect(tmp_path)
    
    (tmp_path / "go.mod").write_text("", encoding="utf-8")
    assert provider.detect(tmp_path)

def test_go_provider_parse_go_sum(tmp_path):
    sum_content = """
github.com/gin-gonic/gin v1.7.7 h1:ODqUxUz/35IPg0HQXKC54qmw57coLvTpqgG15S3xsp0=
github.com/gin-gonic/gin v1.7.7/go.mod h1:h4+ut75IQG9nUu9z8c8zY8vN2SspL1tF9nJ15S3xsp0=
github.com/go-playground/validator/v10 v10.4.1 h1:xxxx
"""
    (tmp_path / "go.sum").write_text(sum_content, encoding="utf-8")
    
    provider = GoProvider()
    packages = provider.discover_packages(tmp_path)
    
    assert len(packages) == 2
    names = {pkg.name for pkg in packages}
    assert "github.com/gin-gonic/gin" in names
    assert "github.com/go-playground/validator/v10" in names
