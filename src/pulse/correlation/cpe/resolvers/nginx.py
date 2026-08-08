from typing import List
from pulse.domain.models import TechnologyCategory
from pulse.website.inventory.models import InventoryTechnology
from pulse.correlation.models import CPECandidate, ResolverMatchType
from pulse.correlation.cpe.resolvers.base import BaseCPEResolver

class NginxResolver(BaseCPEResolver):
    resolver_id = "nginx"
    resolver_name = "Nginx CPE Resolver"
    priority = 100
    supported_categories = [TechnologyCategory.SERVER]

    def can_resolve(self, tech: InventoryTechnology) -> bool:
        return tech.name.lower() == "nginx"

    def resolve(self, tech: InventoryTechnology) -> List[CPECandidate]:
        if not self.can_resolve(tech):
            return []
            
        ver = tech.version
        
        return [
            CPECandidate(
                cpe_template="cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
                detected_version=ver,
                resolved_cpe=f"cpe:2.3:a:nginx:nginx:{ver}:*:*:*:*:*:*:*" if ver else None,
                confidence=100,
                source="resolver:nginx",
                vendor="nginx",
                product="nginx",
                exact_version_match=True,
                match_type=ResolverMatchType.EXACT
            ),
            CPECandidate(
                cpe_template="cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
                detected_version=ver,
                resolved_cpe=f"cpe:2.3:a:f5:nginx:{ver}:*:*:*:*:*:*:*" if ver else None,
                confidence=90,
                source="resolver:nginx",
                vendor="f5",
                product="nginx",
                exact_version_match=True,
                match_type=ResolverMatchType.ALIAS
            )
        ]
