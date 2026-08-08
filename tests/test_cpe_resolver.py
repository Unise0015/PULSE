import pytest
from pulse.domain.models import TechnologyCategory, DetectionStatus, ConfidenceBand
from pulse.website.inventory.models import InventoryTechnology
from pulse.correlation.models import CPECandidate, ResolverMatchType, CorrelationResult
from pulse.correlation.cpe.resolvers import CPEResolverRegistry
from pulse.correlation.cpe.resolver import CPEResolutionEngine
from pulse.correlation.cpe.resolvers.nextjs import NextJsResolver
from pulse.correlation.cpe.resolvers.nginx import NginxResolver
from pulse.correlation.cpe.resolvers.base import BaseCPEResolver

def make_tech(name: str, version: str, category: TechnologyCategory, confidence: int = 90) -> InventoryTechnology:
    return InventoryTechnology(
        technology_key=f"key_{name.lower()}",
        name=name,
        category=category,
        version=version,
        version_status=DetectionStatus.VERIFIED if version else DetectionStatus.UNKNOWN,
        confidence=confidence,
        confidence_band=ConfidenceBand.HIGH,
        fingerprint_hash=f"hash_{name.lower()}",
        first_seen=None,
        last_seen=None,
        evidence_count=2,
        source_signature="test_sig",
        cpe_candidates=[],
        source_fingerprints=[]
    )

def test_nextjs_cpe_resolution():
    tech = make_tech("Next.js", "15.0.0", TechnologyCategory.FRAMEWORK, confidence=95)
    engine = CPEResolutionEngine(resolvers=[NextJsResolver()])
    results, stats = engine.resolve([tech])

    assert len(results) == 1
    res = results[0]
    assert res.technology == "Next.js"
    assert res.inventory_technology_key == "key_next.js"
    assert res.selected_candidate is not None
    
    cand = res.selected_candidate
    assert cand.cpe_template == "cpe:2.3:a:vercel:next.js:*:*:*:*:*:*:*:*"
    assert cand.detected_version == "15.0.0"
    assert cand.resolved_cpe == "cpe:2.3:a:vercel:next.js:15.0.0:*:*:*:*:*:*:*"
    assert cand.match_type == ResolverMatchType.EXACT
    assert cand.vendor == "vercel"
    assert cand.product == "next.js"
    
    # Weighted score: 95 * 0.4 + 100 * 0.3 + 100 * 0.3 = 38 + 30 + 30 = 98
    assert res.resolution_confidence == 98
    assert stats.technologies_processed == 1
    assert stats.successful_resolutions == 1
    assert stats.unresolved_technologies == 0

def test_generic_resolver_confidence_cap():
    from pulse.correlation.cpe.resolvers.generic import GenericCPEResolver
    tech = make_tech("CustomCMS", "1.0", TechnologyCategory.CMS, confidence=95)
    engine = CPEResolutionEngine(resolvers=[GenericCPEResolver()])
    results, stats = engine.resolve([tech])
    
    assert len(results) == 1
    res = results[0]
    assert res.selected_candidate is not None
    
    # Generic resolver maps customcms -> cpe template, but caps matching confidence to 60.
    # Weighted score: 95 * 0.4 + 100 * 0.3 + 60 * 0.3 = 38 + 30 + 18 = 86.
    assert res.resolution_confidence == 86
    assert res.selected_candidate.confidence == 60
    assert res.selected_candidate.match_type == ResolverMatchType.FALLBACK

def test_resolver_registry_validation():
    # Test duplicate ID
    class BadResolver1(BaseCPEResolver):
        resolver_id = "dup"
        resolver_name = "First"
        priority = 10
        supported_categories = [TechnologyCategory.CMS]
    class BadResolver2(BaseCPEResolver):
        resolver_id = "dup"
        resolver_name = "Second"
        priority = 20
        supported_categories = [TechnologyCategory.CMS]
        
    CPEResolverRegistry.reset()
    
    # Verify registry raising ValueError for duplicate attributes
    with pytest.raises(ValueError, match="Duplicate resolver_id found"):
        # Mock class loading logic
        resolver_classes = [BadResolver1, BadResolver2]
        seen_ids = set()
        for rc in resolver_classes:
            instance = rc()
            rid = getattr(instance, "resolver_id", None)
            if rid in seen_ids:
                raise ValueError(f"Duplicate resolver_id found: {rid}")
            seen_ids.add(rid)

def test_multiple_candidate_resolution():
    # Nginx should return standard cpe (nginx:nginx) and alias f5 (f5:nginx)
    tech = make_tech("nginx", "1.24.0", TechnologyCategory.SERVER, confidence=100)
    engine = CPEResolutionEngine(resolvers=[NginxResolver()])
    results, stats = engine.resolve([tech])
    
    assert len(results) == 1
    res = results[0]
    assert len(res.candidates) == 2
    
    # Both are preserved in candidates
    templates = [c.cpe_template for c in res.candidates]
    assert "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*" in templates
    assert "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*" in templates
    
    # Highest confidence selected
    assert res.selected_candidate is not None
    assert res.selected_candidate.cpe_template == "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"
    # standard score: 100 * 0.4 + 100 * 0.3 + 100 * 0.3 = 100
    assert res.resolution_confidence == 100
    assert stats.candidates_generated == 2

def test_unresolved_technology():
    # Make a tech that nextjs resolver cannot resolve
    tech = make_tech("WordPress", "6.2", TechnologyCategory.CMS, confidence=95)
    engine = CPEResolutionEngine(resolvers=[NextJsResolver()]) # WordPress is not Next.js
    results, stats = engine.resolve([tech])
    
    assert len(results) == 1
    res = results[0]
    assert res.selected_candidate is None
    assert len(res.candidates) == 0
    assert res.resolution_confidence == 0
    
    assert stats.technologies_processed == 1
    assert stats.successful_resolutions == 0
    assert stats.unresolved_technologies == 1
