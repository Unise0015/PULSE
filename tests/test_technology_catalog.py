import pytest
from pulse.website.technology_catalog import TECHNOLOGY_CATALOG

def test_alias_uniqueness():
    """Verify that no two distinct technologies share the same alias."""
    seen_aliases = {}
    for tech_key, tech in TECHNOLOGY_CATALOG.items():
        aliases = tech.get("aliases", [])
        for alias in aliases:
            cleaned_alias = alias.strip().lower()
            if cleaned_alias in seen_aliases:
                other_tech = seen_aliases[cleaned_alias]
                pytest.fail(f"Overlap detected: alias '{cleaned_alias}' is defined for both '{tech_key}' and '{other_tech}'")
            seen_aliases[cleaned_alias] = tech_key

def test_lookup_consistency():
    """Verify that every catalog entry has the required metadata attributes."""
    required_fields = ["display_name", "lookup_strategy", "supports_versions", "coverage"]
    
    for tech_key, tech in TECHNOLOGY_CATALOG.items():
        for field in required_fields:
            assert field in tech, f"Technology '{tech_key}' is missing required field: {field}"
            
        assert isinstance(tech["display_name"], str)
        assert isinstance(tech["supports_versions"], bool)
        assert tech["lookup_strategy"] in ("osv", "nvd", "both")
        assert tech["coverage"] in ("full", "partial", "experimental")

def test_mapper_validation():
    """Verify strategy mapping rules:
    - nvd / both must have cpe
    - osv / both must have ecosystem and package
    """
    for tech_key, tech in TECHNOLOGY_CATALOG.items():
        strategy = tech["lookup_strategy"]
        
        if strategy in ("nvd", "both"):
            assert "cpe" in tech, f"Technology '{tech_key}' has strategy '{strategy}' but lacks 'cpe' mapping."
            assert tech["cpe"].startswith("cpe:2.3:a:"), f"Technology '{tech_key}' cpe format is invalid: {tech['cpe']}"
            
        if strategy in ("osv", "both"):
            assert "ecosystem" in tech, f"Technology '{tech_key}' has strategy '{strategy}' but lacks 'ecosystem' mapping."
            assert "package" in tech, f"Technology '{tech_key}' has strategy '{strategy}' but lacks 'package' mapping."
