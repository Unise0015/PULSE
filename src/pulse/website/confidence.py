from abc import ABC, abstractmethod
from typing import List
from pulse.domain.models import DetectionEvidence, ConfidenceBand, DetectionMethod

class ConfidenceCalculator(ABC):
    @abstractmethod
    def calculate(self, evidence: List[DetectionEvidence]) -> int:
        """Calculate confidence score (0-100) based on list of evidence."""
        pass

class WeightedMaxBonusCalculator(ConfidenceCalculator):
    # Method weights
    METHOD_WEIGHTS = {
        DetectionMethod.HEADER: 1.0,
        DetectionMethod.SCRIPT: 0.9,
        DetectionMethod.META: 0.8,
        DetectionMethod.HTML: 0.8,
        DetectionMethod.COOKIE: 0.7,
        DetectionMethod.URL_PATTERN: 0.6,
    }

    def calculate(self, evidence: List[DetectionEvidence]) -> int:
        if not evidence:
            return 0

        # Calculate weighted score for each evidence item
        scores = []
        for ev in evidence:
            weight = self.METHOD_WEIGHTS.get(ev.method, 0.5)
            weighted_score = ev.confidence * weight
            scores.append(weighted_score)

        if not scores:
            return 0

        max_score = max(scores)
        # Find index of max score to exclude it from others
        max_idx = scores.index(max_score)
        
        other_scores = [score for idx, score in enumerate(scores) if idx != max_idx]
        bonus = sum(other_scores) * 0.25
        bonus_capped = min(bonus, 20.0)

        final_score = min(max_score + bonus_capped, 100.0)
        return int(round(final_score))

def get_confidence_band(score: int) -> ConfidenceBand:
    if score >= 95:
        return ConfidenceBand.VERIFIED
    elif score >= 70:
        return ConfidenceBand.HIGH
    elif score >= 40:
        return ConfidenceBand.MEDIUM
    else:
        return ConfidenceBand.LOW
