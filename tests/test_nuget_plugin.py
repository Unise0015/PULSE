import json
import pytest
from pathlib import Path
from pulse.ecosystems.nuget.plugin import NuGetPlugin
from pulse.ecosystems.base import ScanContext, ScannerConfig
import logging

def test_nuget_detection(tmp_path):
    plugin = NuGetPlugin()
    context = ScanContext(root=tmp_path, config=ScannerConfig(), cache=None, history=None, logger=logging.getLogger())
    assert not plugin.detect(context)

    (tmp_path / "App.csproj").write_text("<Project></Project>", encoding="utf-8")
    assert plugin.detect(context)

def test_nuget_packages_config_parsing(tmp_path):
    plugin = NuGetPlugin()
    
    config_content = """<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="Newtonsoft.Json" version="13.0.1" targetFramework="net48" />
  <package id="EntityFramework" version="6.4.4" targetFramework="net48" />
</packages>
"""
    (tmp_path / "packages.config").write_text(config_content, encoding="utf-8")
    
    context = ScanContext(root=tmp_path, config=ScannerConfig(), cache=None, history=None, logger=logging.getLogger())
    raw_deps = plugin.parse(context)
    
    names = [d.name for d in raw_deps]
    versions = {d.name: d.version_spec for d in raw_deps}
    
    assert "Newtonsoft.Json" in names
    assert versions["Newtonsoft.Json"] == "13.0.1"
    assert "EntityFramework" in names
    assert versions["EntityFramework"] == "6.4.4"

def test_nuget_csproj_cpm_parsing(tmp_path):
    plugin = NuGetPlugin()
    
    # Write Central Package Management props
    cpm_content = """<?xml version="1.0" encoding="utf-8"?>
<Project>
  <PropertyGroup>
    <ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally>
  </PropertyGroup>
  <ItemGroup>
    <PackageVersion Include="Newtonsoft.Json" Version="13.0.3" />
    <PackageVersion Include="Microsoft.Extensions.Logging" Version="7.0.0" />
  </ItemGroup>
</Project>
"""
    (tmp_path / "Directory.Packages.props").write_text(cpm_content, encoding="utf-8")
    
    # Write csproj using CPM (no Version attribute on PackageReference)
    csproj_content = """<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" />
    <PackageReference Include="Microsoft.Extensions.Logging" />
    <PackageReference Include="Custom.Local.Pkg" Version="1.0.0" />
  </ItemGroup>
</Project>
"""
    (tmp_path / "App.csproj").write_text(csproj_content, encoding="utf-8")
    
    context = ScanContext(root=tmp_path, config=ScannerConfig(), cache=None, history=None, logger=logging.getLogger())
    raw_deps = plugin.parse(context)
    
    names = [d.name for d in raw_deps]
    versions = {d.name: d.version_spec for d in raw_deps}
    
    assert "Newtonsoft.Json" in names
    assert versions["Newtonsoft.Json"] == "13.0.3"
    
    assert "Microsoft.Extensions.Logging" in names
    assert versions["Microsoft.Extensions.Logging"] == "7.0.0"
    
    assert "Custom.Local.Pkg" in names
    assert versions["Custom.Local.Pkg"] == "1.0.0"

def test_nuget_lockfile_parsing(tmp_path):
    plugin = NuGetPlugin()
    
    lock_content = {
        "version": 1,
        "dependencies": {
            ".NETCoreApp,Version=v6.0": {
                "Newtonsoft.Json": {
                    "type": "Direct",
                    "resolved": "13.0.3",
                    "contentHash": "Hash1"
                },
                "System.Text.Json": {
                    "type": "Transitive",
                    "resolved": "6.0.0",
                    "contentHash": "Hash2"
                }
            }
        }
    }
    
    # Create a subfolder with lockfile
    sub_dir = tmp_path / "App"
    sub_dir.mkdir()
    (sub_dir / "packages.lock.json").write_text(json.dumps(lock_content), encoding="utf-8")
    
    context = ScanContext(root=tmp_path, config=ScannerConfig(), cache=None, history=None, logger=logging.getLogger())
    raw_deps = plugin.parse(context)
    
    names = [d.name for d in raw_deps]
    versions = {d.name: d.version_spec for d in raw_deps}
    dep_types = {d.name: d.dependency_type for d in raw_deps}
    
    assert "Newtonsoft.Json" in names
    assert versions["Newtonsoft.Json"] == "13.0.3"
    assert dep_types["Newtonsoft.Json"] == "DIRECT"
    
    assert "System.Text.Json" in names
    assert versions["System.Text.Json"] == "6.0.0"
    assert dep_types["System.Text.Json"] == "TRANSITIVE"
