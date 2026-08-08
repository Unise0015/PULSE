from typing import List
from pulse.domain.models import TechnologyCategory
from pulse.website.inventory.models import InventoryTechnology
from pulse.correlation.models import CPECandidate, ResolverMatchType
from pulse.correlation.cpe.resolvers.base import BaseCPEResolver

class ApacheResolver(BaseCPEResolver):
    resolver_id = "apache"
    resolver_name = "Apache HTTP Server CPE Resolver"
    priority = 100
    supported_categories = [TechnologyCategory.SERVER]

    def can_resolve(self, tech: InventoryTechnology) -> bool:
        name_clean = tech.name.lower()
        return name_clean == "apache" or "apache http" in name_clean or name_clean == "httpd"

    def resolve(self, tech: InventoryTechnology) -> List[CPECandidate]:
        if not self.can_resolve(tech):
            return []
            
        ver = tech.version
        resolved = f"cpe:2.3:a:apache:http_server:{ver}:*:*:*:*:*:*:*" if ver else None
        
        return [
            CPECandidate(
                cpe_template="cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                detected_version=ver,
                resolved_cpe=resolved,
                confidence=100,
                source="resolver:apache",
                vendor="apache",
                product="http_server",
                exact_version_match=True,
                match_type=ResolverMatchType.EXACT
            )
        ]
