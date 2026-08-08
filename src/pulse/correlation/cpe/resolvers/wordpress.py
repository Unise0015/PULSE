from typing import List
from pulse.domain.models import TechnologyCategory
from pulse.website.inventory.models import InventoryTechnology
from pulse.correlation.models import CPECandidate, ResolverMatchType
from pulse.correlation.cpe.resolvers.base import BaseCPEResolver

class WordPressResolver(BaseCPEResolver):
    resolver_id = "wordpress"
    resolver_name = "WordPress CPE Resolver"
    priority = 100
    supported_categories = [TechnologyCategory.CMS]

    def can_resolve(self, tech: InventoryTechnology) -> bool:
        return tech.name.lower() == "wordpress"

    def resolve(self, tech: InventoryTechnology) -> List[CPECandidate]:
        if not self.can_resolve(tech):
            return []
            
        ver = tech.version
        resolved = f"cpe:2.3:a:wordpress:wordpress:{ver}:*:*:*:*:*:*:*" if ver else None
        
        return [
            CPECandidate(
                cpe_template="cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*",
                detected_version=ver,
                resolved_cpe=resolved,
                confidence=100,
                source="resolver:wordpress",
                vendor="wordpress",
                product="wordpress",
                exact_version_match=True,
                match_type=ResolverMatchType.EXACT
            )
        ]
