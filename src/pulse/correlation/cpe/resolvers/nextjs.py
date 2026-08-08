from typing import List
from pulse.domain.models import TechnologyCategory
from pulse.website.inventory.models import InventoryTechnology
from pulse.correlation.models import CPECandidate, ResolverMatchType
from pulse.correlation.cpe.resolvers.base import BaseCPEResolver

class NextJsResolver(BaseCPEResolver):
    resolver_id = "nextjs"
    resolver_name = "Next.js CPE Resolver"
    priority = 100
    supported_categories = [TechnologyCategory.FRAMEWORK]

    def can_resolve(self, tech: InventoryTechnology) -> bool:
        return tech.name.lower() == "next.js"

    def resolve(self, tech: InventoryTechnology) -> List[CPECandidate]:
        if not self.can_resolve(tech):
            return []
            
        ver = tech.version
        resolved = f"cpe:2.3:a:vercel:next.js:{ver}:*:*:*:*:*:*:*" if ver else None
        
        return [
            CPECandidate(
                cpe_template="cpe:2.3:a:vercel:next.js:*:*:*:*:*:*:*:*",
                detected_version=ver,
                resolved_cpe=resolved,
                confidence=100,
                source="resolver:nextjs",
                vendor="vercel",
                product="next.js",
                exact_version_match=True,
                match_type=ResolverMatchType.EXACT
            )
        ]
