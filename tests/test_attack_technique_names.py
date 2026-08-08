import pytest
from pulse.domain.models import AttackTechnique

class TestAttackTechniqueNames:
    """Verify ATT&CK technique name resolution and fallback handling."""

    def test_known_technique_has_name(self):
        tech = AttackTechnique(
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            tactic="Initial Access",
            confidence="High"
        )
        assert tech.technique_id == "T1190"
        assert tech.technique_name == "Exploit Public-Facing Application"

    def test_unknown_technique_fallback(self):
        tech = AttackTechnique(
            technique_id="T9999",
            technique_name="",
            tactic="Unknown",
            confidence="Low"
        )
        display_name = tech.technique_name or "Technique name unavailable"
        assert display_name == "Technique name unavailable"
        assert tech.technique_id == "T9999"
