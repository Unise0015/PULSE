from abc import ABC, abstractmethod
from typing import List, Dict, Tuple, Optional, Set
from pulse.domain.models import DetectionEvidence, ConfidenceBand, DetectionMethod, TechnologyFingerprint


class ConfidenceCalculator(ABC):
    @abstractmethod
    def calculate(self, evidence: List[DetectionEvidence]) -> int:
        """Calculate confidence score (0-100) based on list of evidence."""
        pass


class WeightedMaxBonusCalculator(ConfidenceCalculator):
    """
    Trust-weighted multi-signal confidence calculator.
    Inverts legacy trust hierarchy by weighting resilient structural/DOM/AST signals
    (0.95) over spoofable HTTP response headers (0.50), and rewards independent vector corroboration.
    """
    METHOD_WEIGHTS = {
        DetectionMethod.HTML: 0.95,        # DOM attributes, __NEXT_DATA__, ng-version
        DetectionMethod.SCRIPT: 0.90,      # Asset paths, chunk manifests, SRI hashes
        DetectionMethod.META: 0.85,        # Meta generator tags
        DetectionMethod.COOKIE: 0.75,      # Framework session identifiers
        DetectionMethod.URL_PATTERN: 0.60, # Route patterns
        DetectionMethod.HEADER: 0.50,      # Server, X-Powered-By (easily spoofed/stripped)
    }

    def calculate(self, evidence: List[DetectionEvidence]) -> int:
        if not evidence:
            return 0

        # Calculate weighted score for each evidence item
        scores = []
        distinct_methods: Set[DetectionMethod] = set()

        for ev in evidence:
            weight = self.METHOD_WEIGHTS.get(ev.method, 0.50)
            weighted_score = ev.confidence * weight
            scores.append(weighted_score)
            distinct_methods.add(ev.method)

        if not scores:
            return 0

        max_score = max(scores)
        max_idx = scores.index(max_score)
        
        other_scores = [score for idx, score in enumerate(scores) if idx != max_idx]
        bonus = sum(other_scores) * 0.20
        bonus_capped = min(bonus, 15.0)

        # Independent Vector Corroboration Multiplier:
        # Multiple independent signal types agreeing (e.g. Header + DOM + Script) > multiple hits in 1 type
        corroboration_bonus = 0.0
        if len(distinct_methods) >= 3:
            corroboration_bonus = 15.0
        elif len(distinct_methods) == 2:
            corroboration_bonus = 10.0

        final_score = min(max_score + bonus_capped + corroboration_bonus, 100.0)
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


class SignalDisagreementDetector:
    """
    Identifies contradictory or spoofed signals across independent detection vectors.
    """
    @staticmethod
    def detect_conflicts(
        technologies: List[TechnologyFingerprint],
        headers: Dict[str, str]
    ) -> List[str]:
        conflicts = []
        norm_headers = {k.lower().strip(): v for k, v in headers.items()}
        server_header = norm_headers.get("server", "").lower()
        tech_names = {t.name.lower() for t in technologies}

        # Conflict 1: Server header claims Apache, but structural signals detect Nginx/IIS
        if "apache" in server_header and "nginx" in tech_names:
            conflicts.append("Header Discrepancy: 'Server: Apache' header contradicts Nginx structural signatures.")
        elif "nginx" in server_header and "apache http server" in tech_names:
            conflicts.append("Header Discrepancy: 'Server: Nginx' header contradicts Apache HTTP Server structural signatures.")
        elif "microsoft-iis" in server_header and ("django" in tech_names or "ruby on rails" in tech_names):
            conflicts.append(f"Header Discrepancy: 'Server: {server_header}' header contradicts {', '.join(tech_names & {'django', 'ruby on rails'})} framework signals.")

        # Conflict 2: Spring Boot / Java application behind generic proxy
        if "spring boot" in tech_names and ("apache" in server_header or "nginx" in server_header):
            conflicts.append(f"Architecture Context: Application is running Spring Boot behind reverse proxy ({server_header.split()[0]}).")

        return conflicts
