from pathlib import Path
from typing import List
from pulse.ecosystems.base import EcosystemRegistry, DetectionCandidate

class EcosystemDetector:
    def __init__(self, registry: EcosystemRegistry):
        self.registry = registry

    def detect_ecosystem(self, package_name: str, current_dir: Path) -> List[DetectionCandidate]:
        candidates: List[DetectionCandidate] = []
        
        # 1. Local lockfile/project detection (confidence: 100)
        lockfile_map = {
            "requirements.txt": "Python",
            "package-lock.json": "Node.js",
            "package.json": "Node.js",
            "Cargo.lock": "Rust",
            "go.mod": "Go",
            "go.sum": "Go",
            "Gemfile.lock": "Ruby",
            "composer.lock": "Composer"
        }
        
        for lockfile, eco_name in lockfile_map.items():
            path = current_dir / lockfile
            if path.exists():
                try:
                    content = path.read_text(encoding="utf-8")
                    # Simple text match is usually sufficient for heuristics
                    if f"{package_name}" in content:
                        # Avoid duplicates
                        if not any(c.ecosystem == eco_name for c in candidates):
                            candidates.append(DetectionCandidate(
                                ecosystem=eco_name,
                                confidence=100,
                                source=lockfile
                            ))
                except Exception:
                    pass

        # 2. Provider Name Confidence Checks
        for provider in self.registry.get_all_providers():
            confidence = provider.package_name_confidence(package_name)
            if confidence > 0:
                if not any(c.ecosystem == provider.display_name for c in candidates):
                    candidates.append(DetectionCandidate(
                        ecosystem=provider.display_name,
                        confidence=confidence,
                        source="provider naming heuristic"
                    ))

        # Sort candidates by confidence descending
        candidates.sort(key=lambda c: c.confidence, reverse=True)
        return candidates

    def resolve(self, candidates: List[DetectionCandidate]) -> List[DetectionCandidate]:
        """
        Returns a list of top candidates. If there's a tie for first place, returns all tied candidates.
        """
        if not candidates:
            return []
            
        top_confidence = candidates[0].confidence
        return [c for c in candidates if c.confidence == top_confidence]
