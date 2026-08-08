from typing import Tuple
from pulse.domain.models import ConfidenceBand

def get_confidence_band(score: int) -> ConfidenceBand:
    if score >= 95:
        return ConfidenceBand.VERIFIED
    elif score >= 70:
        return ConfidenceBand.HIGH
    elif score >= 40:
        return ConfidenceBand.MEDIUM
    else:
        return ConfidenceBand.LOW

def should_correlate(confidence: int) -> Tuple[bool, bool]:
    """Determine lookup eligibility and warnings based on detection confidence.
    
    Args:
        confidence: Detection confidence score (0-100)
        
    Returns:
        Tuple[do_lookup, show_warning]
    """
    if confidence < 40:
        return False, False
    elif confidence < 70:
        return True, True
    return True, False
