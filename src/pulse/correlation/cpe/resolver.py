from typing import List, Tuple
from pulse.website.inventory.models import InventoryTechnology
from pulse.domain.models import DetectionStatus
from pulse.correlation.models import CorrelationResult, CPECandidate, CorrelationStatistics
from pulse.correlation.cpe.resolvers import CPEResolverRegistry

class CPEResolutionEngine:
    def __init__(self, resolvers=None):
        if resolvers is not None:
            self.resolvers = resolvers
        else:
            self.resolvers = CPEResolverRegistry.load()

    def resolve(self, technologies: List[InventoryTechnology]) -> Tuple[List[CorrelationResult], CorrelationStatistics]:
        results = []
        
        candidates_generated_total = 0
        successful_resolutions_count = 0
        unresolved_technologies_count = 0

        for tech in technologies:
            tech_candidates = []
            
            # Run matching resolvers
            for resolver in self.resolvers:
                if resolver.can_resolve(tech):
                    try:
                        resolved = resolver.resolve(tech)
                        if resolved:
                            tech_candidates.extend(resolved)
                    except Exception:
                        pass
            
            # Deduplicate templates to avoid duplicate candidates
            unique_candidates = []
            seen_templates = set()
            for cand in tech_candidates:
                if cand.cpe_template not in seen_templates:
                    seen_templates.add(cand.cpe_template)
                    unique_candidates.append(cand)

            candidates_generated_total += len(unique_candidates)
            
            candidates_with_scores = []
            for cand in unique_candidates:
                # 1. Version Confidence
                if tech.version:
                    if tech.version_status == DetectionStatus.VERIFIED:
                        version_conf = 100
                    elif tech.version_status == DetectionStatus.ESTIMATED:
                        version_conf = 70
                    else:
                        version_conf = 100
                else:
                    version_conf = 0
                
                # 2. Weighted score: 40% tech, 30% version, 30% resolver candidate
                score = int(tech.confidence * 0.4 + version_conf * 0.3 + cand.confidence * 0.3)
                candidates_with_scores.append((cand, score))

            if candidates_with_scores:
                # Sort descending by resolution score, then by candidate confidence
                candidates_with_scores.sort(key=lambda x: (x[1], x[0].confidence), reverse=True)
                selected_candidate, resolution_confidence = candidates_with_scores[0]
                successful_resolutions_count += 1
            else:
                selected_candidate = None
                resolution_confidence = 0
                unresolved_technologies_count += 1

            results.append(CorrelationResult(
                technology=tech.name,
                inventory_technology_key=tech.technology_key,
                candidates=unique_candidates,
                selected_candidate=selected_candidate,
                resolution_confidence=resolution_confidence
            ))

        stats = CorrelationStatistics(
            technologies_processed=len(technologies),
            candidates_generated=candidates_generated_total,
            successful_resolutions=successful_resolutions_count,
            unresolved_technologies=unresolved_technologies_count
        )

        return results, stats
