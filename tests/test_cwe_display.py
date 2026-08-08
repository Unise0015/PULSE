import pytest
from pulse.vulnerability.cwe_registry import CWERegistry

class TestCWEDisplay:
    """Verify CWE formatting uses CWERegistry and avoids 'CWE-XX (None)'."""

    def test_cwe_with_name(self):
        result = CWERegistry.format_cwe("CWE-89", "SQL Injection")
        assert result == "CWE-89 (SQL Injection)"

    def test_cwe_with_catalog_resolution(self):
        result = CWERegistry.format_cwe("CWE-89", None)
        assert result == "CWE-89 (SQL Injection)"

    def test_cwe_without_known_name(self):
        result = CWERegistry.format_cwe("CWE-9999", None)
        assert result == "CWE-9999"

    def test_cwe_never_returns_none_in_parentheses(self):
        result = CWERegistry.format_cwe("CWE-89", "None")
        assert result != "CWE-89 (None)"
        assert result == "CWE-89 (SQL Injection)"

    test_unassigned = [
        (None, None, "Unassigned"),
        ("", "", "Unassigned"),
        ("Unassigned", None, "Unassigned"),
        ("NONE", None, "Unassigned")
    ]

    @pytest.mark.parametrize("cwe_id, cwe_name, expected", test_unassigned)
    def test_cwe_unassigned(self, cwe_id, cwe_name, expected):
        assert CWERegistry.format_cwe(cwe_id, cwe_name) == expected
