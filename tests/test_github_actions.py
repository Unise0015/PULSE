import pytest
from pathlib import Path
from pulse.ecosystems.github_actions.plugin import GitHubActionsPlugin
from pulse.ecosystems.base import ScanContext, ScannerConfig
import logging

def test_github_actions_detection(tmp_path):
    plugin = GitHubActionsPlugin()
    context = ScanContext(root=tmp_path, config=ScannerConfig(), cache=None, history=None, logger=logging.getLogger())
    assert not plugin.detect(context)

    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    assert not plugin.detect(context)

    (workflow_dir / "build.yml").write_text("name: Build", encoding="utf-8")
    assert plugin.detect(context)

def test_github_actions_parsing(tmp_path):
    plugin = GitHubActionsPlugin()
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    
    workflow_content = """
name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4
      - name: Setup Node
        uses: actions/setup-node@v3.8.1
      - name: Local Action
        uses: ./.github/actions/setup-local
      - name: Docker Action
        uses: docker://alpine:3.18
      - name: Action with SHA
        uses: actions/cache@88522ab9f39a2b69f356028d901f8d5386f555c4
"""
    (workflow_dir / "ci.yml").write_text(workflow_content, encoding="utf-8")
    
    context = ScanContext(root=tmp_path, config=ScannerConfig(), cache=None, history=None, logger=logging.getLogger())
    raw_deps = plugin.parse(context)
    
    names = [d.name for d in raw_deps]
    versions = [d.version_spec for d in raw_deps]
    
    assert "actions/checkout" in names
    assert "v4" in versions
    assert "actions/setup-node" in names
    assert "v3.8.1" in versions
    assert "actions/cache" in names
    assert "88522ab9f39a2b69f356028d901f8d5386f555c4" in versions
    
    # Verify local and docker actions are ignored
    assert "./.github/actions/setup-local" not in names
    assert "docker://alpine" not in names
