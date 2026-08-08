"""Tests for upgrade command generation logic."""
import pytest
from pulse.ui import get_recommended_command


class TestRecommendedCommand:
    def test_python_recommended(self):
        cmd = get_recommended_command("django", "python")
        assert cmd == "pip install --upgrade django"

    def test_pypi_recommended(self):
        cmd = get_recommended_command("flask", "pypi")
        assert cmd == "pip install --upgrade flask"

    def test_npm_recommended(self):
        cmd = get_recommended_command("lodash", "npm")
        assert cmd == "npm update lodash"

    def test_node_recommended(self):
        cmd = get_recommended_command("express", "node")
        assert cmd == "npm update express"

    def test_unknown_ecosystem_recommended(self):
        cmd = get_recommended_command("libcurl", "c")
        assert cmd == "Upgrade libcurl to latest"
