from typing import List
from pulse.domain.models import TechnologyCategory
from pulse.website.inventory.models import InventoryTechnology
from pulse.correlation.models import CPECandidate

class BaseCPEResolver:
    resolver_id: str
    resolver_name: str
    priority: int
    supported_categories: List[TechnologyCategory]

    def can_resolve(self, tech: InventoryTechnology) -> bool:
        raise NotImplementedError()

    def resolve(self, tech: InventoryTechnology) -> List[CPECandidate]:
        raise NotImplementedError()
