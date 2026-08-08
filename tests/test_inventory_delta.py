import pytest
from pulse.domain.models import TechnologyCategory, DetectionStatus, ConfidenceBand
from pulse.website.inventory.models import InventoryTechnology
from pulse.website.inventory.delta import compare_inventory, VersionChange

def make_tech(name: str, version: str, category: TechnologyCategory) -> InventoryTechnology:
    import hashlib
    tech_key = hashlib.sha256(f"{name.lower()}:{category.value.lower()}".encode("utf-8")).hexdigest()
    fingerprint_hash = hashlib.sha256(f"{name.lower()}:{version or ''}:{category.value.lower()}".encode("utf-8")).hexdigest()
    return InventoryTechnology(
        technology_key=tech_key,
        name=name,
        category=category,
        version=version,
        version_status=DetectionStatus.VERIFIED if version else DetectionStatus.UNKNOWN,
        confidence=90,
        confidence_band=ConfidenceBand.HIGH,
        fingerprint_hash=fingerprint_hash,
        first_seen=None,
        last_seen=None,
        evidence_count=2,
        source_signature="test_sig",
        cpe_candidates=[],
        source_fingerprints=[]
    )

def test_inventory_delta_added_removed():
    prev = [
        make_tech("Next.js", "14.0.0", TechnologyCategory.FRAMEWORK),
        make_tech("PHP", "8.0.0", TechnologyCategory.RUNTIME)
    ]
    curr = [
        make_tech("Next.js", "14.0.0", TechnologyCategory.FRAMEWORK),
        make_tech("Cloudflare", None, TechnologyCategory.CDN)
    ]
    
    delta = compare_inventory(curr, prev)
    
    assert delta.added == ["Cloudflare"]
    assert delta.removed == ["PHP"]
    assert delta.unchanged == ["Next.js"]
    assert len(delta.upgraded) == 0
    assert len(delta.downgraded) == 0


def test_inventory_delta_upgrade_downgrade():
    prev = [
        make_tech("Next.js", "14.2.0", TechnologyCategory.FRAMEWORK),
        make_tech("Apache", "2.4.58", TechnologyCategory.SERVER)
    ]
    curr = [
        make_tech("Next.js", "15.0.0", TechnologyCategory.FRAMEWORK),
        make_tech("Apache", "2.4.50", TechnologyCategory.SERVER)
    ]
    
    delta = compare_inventory(curr, prev)
    
    assert len(delta.upgraded) == 1
    assert delta.upgraded[0] == VersionChange(technology="Next.js", previous_version="14.2.0", current_version="15.0.0")
    
    assert len(delta.downgraded) == 1
    assert delta.downgraded[0] == VersionChange(technology="Apache", previous_version="2.4.58", current_version="2.4.50")
    
    assert len(delta.added) == 0
    assert len(delta.removed) == 0
    assert len(delta.unchanged) == 0


def test_unknown_version_handling():
    # UNKNOWN -> KNOWN (Next.js unknown -> 15.0.0) -> Should remain in unchanged (version-wise)
    prev1 = [make_tech("Next.js", None, TechnologyCategory.FRAMEWORK)]
    curr1 = [make_tech("Next.js", "15.0.0", TechnologyCategory.FRAMEWORK)]
    
    delta1 = compare_inventory(curr1, prev1)
    assert delta1.unchanged == ["Next.js"]
    assert len(delta1.upgraded) == 0
    
    # KNOWN -> UNKNOWN (Next.js 15.0.0 -> unknown) -> Should remain in unchanged (version-wise)
    prev2 = [make_tech("Next.js", "15.0.0", TechnologyCategory.FRAMEWORK)]
    curr2 = [make_tech("Next.js", None, TechnologyCategory.FRAMEWORK)]
    
    delta2 = compare_inventory(curr2, prev2)
    assert delta2.unchanged == ["Next.js"]
    assert len(delta2.downgraded) == 0
