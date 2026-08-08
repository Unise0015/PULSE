from typing import List
from pulse.domain.models import TechnologyCategory
from pulse.website.inventory.models import InventoryTechnology
from pulse.correlation.models import CPECandidate, ResolverMatchType
from pulse.correlation.cpe.resolvers.base import BaseCPEResolver

class GenericCPEResolver(BaseCPEResolver):
    resolver_id = "generic"
    resolver_name = "Generic CPE Resolver"
    priority = 10
    supported_categories = list(TechnologyCategory)

    def can_resolve(self, tech: InventoryTechnology) -> bool:
        # Generic resolver is a fallback and can process any technology
        return True

    def resolve(self, tech: InventoryTechnology) -> List[CPECandidate]:
        ver = tech.version
        name_clean = tech.name.strip().lower().replace(" ", "_").replace(".", "_")
        cpe_template = f"cpe:2.3:a:{name_clean}:{name_clean}:*:*:*:*:*:*:*:*"
        resolved = f"cpe:2.3:a:{name_clean}:{name_clean}:{ver}:*:*:*:*:*:*:*" if ver else None
        
        # Generic match confidence is capped at 60 max
        cand_conf = min(tech.confidence, 60)
        
        return [
            CPECandidate(
                cpe_template=cpe_template,
                detected_version=ver,
                resolved_cpe=resolved,
                confidence=cand_conf,
                source="resolver:generic",
                vendor=name_clean,
                product=name_clean,
                exact_version_match=False,
                match_type=ResolverMatchType.FALLBACK
            )
        ]
