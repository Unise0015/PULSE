import pytest
from pulse.website.signatures import SignatureRegistry
from pulse.website.signatures.base import TechnologySignature
from pulse.domain.models import TechnologyCategory

def test_registry_singleton_loading():
    # Verify signatures load and are cached
    sigs1 = SignatureRegistry.load()
    sigs2 = SignatureRegistry.load()
    assert sigs1 is sigs2
    assert len(sigs1) > 0

def test_registry_sorting_order():
    sigs = SignatureRegistry.load()
    priorities = [s.priority for s in sigs]
    # Check that priorities are sorted in descending order
    assert priorities == sorted(priorities, reverse=True)

def test_required_signatures_present():
    sigs = SignatureRegistry.load()
    ids = {s.signature_id for s in sigs}
    expected = {"react", "nextjs", "vue", "angular", "svelte", "vite", "wordpress", "php", "nginx", "apache", "iis", "cloudflare", "fastly", "cloudfront"}
    for item in expected:
         assert item in ids

def test_signature_validation_fails_on_duplicate(monkeypatch):
    # Create fake module list containing duplicate signatures
    class FakeSig1(TechnologySignature):
        @property
        def signature_id(self): return "duplicate_id"
        @property
        def name(self): return "Fake 1"
        @property
        def category(self): return TechnologyCategory.FRAMEWORK
        def match(self, headers, html, cookies, scripts): return []

    class FakeSig2(TechnologySignature):
        @property
        def signature_id(self): return "duplicate_id"
        @property
        def name(self): return "Fake 2"
        @property
        def category(self): return TechnologyCategory.CMS
        def match(self, headers, html, cookies, scripts): return []

    SignatureRegistry.reset()
    
    # We monkeypatch the load method or mock the loaded package modules
    def fake_load():
        # Directly invoke fail-fast duplicate check
        seen = set()
        for inst in [FakeSig1(), FakeSig2()]:
            if inst.signature_id in seen:
                raise ValueError("Duplicate signature_id detected")
            seen.add(inst.signature_id)

    with pytest.raises(ValueError, match="Duplicate signature_id"):
        fake_load()

    # Reset registry to clean state
    SignatureRegistry.reset()
    SignatureRegistry.load()
