from dataclasses import dataclass
from typing import List, Optional
from pulse.domain.version import GenericComparator
from pulse.website.inventory.models import InventoryTechnology

@dataclass
class VersionChange:
    technology: str
    previous_version: str
    current_version: str

@dataclass
class InventoryDelta:
    added: List[str]
    removed: List[str]
    upgraded: List[VersionChange]
    downgraded: List[VersionChange]
    unchanged: List[str]

def compare_inventory(
    current: List[InventoryTechnology],
    previous: List[InventoryTechnology]
) -> InventoryDelta:
    added = []
    removed = []
    upgraded = []
    downgraded = []
    unchanged = []

    curr_map = {t.technology_key: t for t in current}
    prev_map = {t.technology_key: t for t in previous}

    def is_unknown(v: Optional[str]) -> bool:
        if not v:
            return True
        v_clean = v.strip().lower()
        return v_clean in ("", "unknown", "none", "null")

    comparator = GenericComparator()

    for key, curr_tech in curr_map.items():
        if key not in prev_map:
            added.append(curr_tech.name)
        else:
            prev_tech = prev_map[key]
            
            curr_v = curr_tech.version
            prev_v = prev_tech.version
            
            if is_unknown(curr_v) or is_unknown(prev_v):
                unchanged.append(curr_tech.name)
            else:
                try:
                    if comparator.compare(curr_v, ">", prev_v):
                        upgraded.append(VersionChange(
                            technology=curr_tech.name,
                            previous_version=prev_v,
                            current_version=curr_v
                        ))
                    elif comparator.compare(curr_v, "<", prev_v):
                        downgraded.append(VersionChange(
                            technology=curr_tech.name,
                            previous_version=prev_v,
                            current_version=curr_v
                        ))
                    else:
                        unchanged.append(curr_tech.name)
                except Exception:
                    unchanged.append(curr_tech.name)

    for key, prev_tech in prev_map.items():
        if key not in curr_map:
            removed.append(prev_tech.name)

    added.sort()
    removed.sort()
    unchanged.sort()
    upgraded.sort(key=lambda x: x.technology.lower())
    downgraded.sort(key=lambda x: x.technology.lower())

    return InventoryDelta(
        added=added,
        removed=removed,
        upgraded=upgraded,
        downgraded=downgraded,
        unchanged=unchanged
    )
