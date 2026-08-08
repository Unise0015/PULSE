from typing import List
from pulse.domain.models import DetectionEvidence, DetectionMethod

def get_confidence_multiplier(evidence: List[DetectionEvidence]) -> float:
    """Calculate the confidence multiplier based on the highest-scoring detection method.
    
    Args:
        evidence: List of DetectionEvidence items for the technology fingerprint
        
    Returns:
        float: Multiplier (0.0 to 1.0)
    """
    if not evidence:
        return 0.60
        
    multipliers = {
        DetectionMethod.HEADER: 1.00,
        DetectionMethod.COOKIE: 0.95,
        DetectionMethod.META: 0.85,
        DetectionMethod.SCRIPT: 0.75,
        DetectionMethod.HTML: 0.75,
        DetectionMethod.URL_PATTERN: 0.60
    }
    
    max_multiplier = 0.60
    for ev in evidence:
        method = ev.method
        mult = multipliers.get(method, 0.60)
        if mult > max_multiplier:
            max_multiplier = mult
            
    return max_multiplier

def calculate_adjusted_risk(risk_score: int, multiplier: float) -> int:
    """Apply the confidence multiplier to a risk score, rounding to the nearest integer.
    
    Args:
        risk_score: Raw Risk Heat Score (0-100)
        multiplier: Confidence multiplier (0.0 to 1.0)
        
    Returns:
        int: Adjusted Risk Score (0-100)
    """
    return int(round(risk_score * multiplier))
