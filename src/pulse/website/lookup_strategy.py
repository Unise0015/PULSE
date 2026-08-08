from enum import Enum
from pulse.website.technology_catalog import TECHNOLOGY_CATALOG

class LookupStrategyType(Enum):
    OSV_ONLY = "osv"
    NVD_ONLY = "nvd"
    OSV_AND_NVD = "both"

def determine_lookup_strategy(tech_key: str) -> LookupStrategyType:
    tech = TECHNOLOGY_CATALOG.get(tech_key.lower())
    if not tech:
        return LookupStrategyType.OSV_AND_NVD
    
    strategy = tech.get("lookup_strategy", "both")
    if strategy == "osv":
        return LookupStrategyType.OSV_ONLY
    elif strategy == "nvd":
        return LookupStrategyType.NVD_ONLY
    return LookupStrategyType.OSV_AND_NVD
