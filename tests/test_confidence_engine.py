import pytest
from pulse.domain.models import DetectionEvidence, DetectionMethod, TechnologyCategory, TechnologyFingerprint, ConfidenceBand
from pulse.website.confidence import WeightedMaxBonusCalculator
from pulse.website.website_fingerprint import WebsiteFingerprintAnalyzer

def test_confidence_calculations():
    calculator = WeightedMaxBonusCalculator()
    
    # Empty evidence
    assert calculator.calculate([]) == 0
    
    # Single high confidence header (HEADER weight = 1.0)
    ev1 = DetectionEvidence(
        method=DetectionMethod.HEADER,
        source="Server",
        value="nginx",
        confidence=90,
        description="Nginx server header"
    )
    # Expected: 90 * 1.0 = 90
    assert calculator.calculate([ev1]) == 90
    
    # Multiple evidence. HEADER (1.0 weight) and META (0.8 weight)
    ev2 = DetectionEvidence(
        method=DetectionMethod.META,
        source="generator",
        value="wordpress",
        confidence=80,
        description="WordPress meta tag"
    )
    # Scores: [90*1.0 = 90, 80*0.8 = 64]
    # Max: 90. Others: [64]. Bonus: 64 * 0.25 = 16.
    # Total: min(90 + 16, 100) = 100
    assert calculator.calculate([ev1, ev2]) == 100


def test_dag_cycle_prevention():
    analyzer = WebsiteFingerprintAnalyzer()
    
    # Create a cyclic technology configuration
    # React -> Svelte -> React
    t1 = TechnologyFingerprint(
        name="React",
        version=None,
        category=TechnologyCategory.UI_LIBRARY,
        parent="Svelte",
        children=["Svelte"]
    )
    t2 = TechnologyFingerprint(
        name="Svelte",
        version=None,
        category=TechnologyCategory.FRAMEWORK,
        parent="React",
        children=["React"]
    )
    
    techs = [t1, t2]
    # Verify _validate_dag throws ValueError on cycle
    with pytest.raises(ValueError, match="Circular dependency cycle"):
        analyzer._validate_dag(techs)

def test_dag_depth_check():
    analyzer = WebsiteFingerprintAnalyzer()
    
    # Build a tree of depth 11: Tech0 -> Tech1 -> ... -> Tech10
    techs = []
    for i in range(11):
        techs.append(TechnologyFingerprint(
            name=f"Tech{i}",
            version=None,
            category=TechnologyCategory.FRAMEWORK,
            parent=f"Tech{i-1}" if i > 0 else None,
            children=[f"Tech{i+1}"] if i < 10 else []
        ))
        
    # Verify _validate_dag throws ValueError on max tree depth exceeded
    with pytest.raises(ValueError, match="Max tree depth"):
        analyzer._validate_dag(techs)
