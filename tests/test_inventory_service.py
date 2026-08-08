import pytest
from pulse.domain.models import WebsiteAssessment, TechnologyFingerprint, TechnologyCategory, DetectionStatus, ConfidenceBand, CPECandidate
from pulse.website.inventory.service import TechnologyInventoryService
from pulse.website.inventory.normalizer import normalize_name

def test_technology_normalization():
    assert normalize_name("nextjs") == "Next.js"
    assert normalize_name("Next.js") == "Next.js"
    assert normalize_name("reactjs") == "React"
    assert normalize_name("React") == "React"
    assert normalize_name("vue.js") == "Vue.js"
    assert normalize_name("vuejs") == "Vue.js"
    assert normalize_name("node.js") == "Node.js"
    assert normalize_name("nodejs") == "Node.js"
    assert normalize_name("custom-tech") == "custom-tech"


def test_duplicate_merging():
    # Construct raw fingerprints with duplicate names (some aliased)
    # reactjs and React should merge into React
    fp1 = TechnologyFingerprint(
        name="reactjs",
        version="17.0.2",
        category=TechnologyCategory.UI_LIBRARY,
        confidence=80,
        evidence_count=3,
        raw_match_count=5,
        version_status=DetectionStatus.VERIFIED,
        signature_id="react_sig_1",
        cpe_candidates=[CPECandidate(cpe="cpe:2.3:a:facebook:react:17.0.2:*:*:*:*:*:*:*", confidence=95)]
    )
    fp2 = TechnologyFingerprint(
        name="React",
        version=None,
        category=TechnologyCategory.UI_LIBRARY,
        confidence=95,
        evidence_count=2,
        raw_match_count=3,
        version_status=DetectionStatus.UNKNOWN,
        signature_id="react_sig_2",
        cpe_candidates=[CPECandidate(cpe="cpe:2.3:a:facebook:react:*:*:*:*:*:*:*:*", confidence=90)]
    )
    
    wa = WebsiteAssessment(
        url="https://example.com",
        technologies=[fp1, fp2],
        security_headers=[]
    )
    
    service = TechnologyInventoryService()
    inventory = service.build_inventory(wa)
    
    # Assert merged record
    assert len(inventory) == 1
    tech = inventory[0]
    
    assert tech.name == "React"
    assert tech.version == "17.0.2" # Chose the one with version
    assert tech.confidence == 95 # Preserved max confidence
    assert tech.evidence_count == 5 # Summed evidence counts (3 + 2)
    assert len(tech.source_fingerprints) == 2
    assert "react_sig_1" in tech.source_fingerprints
    assert "react_sig_2" in tech.source_fingerprints
    
    # CPE candidate union (unique set sorted)
    assert len(tech.cpe_candidates) == 2
    assert tech.cpe_candidates[0] == "cpe:2.3:a:facebook:react:*:*:*:*:*:*:*:*"
    assert tech.cpe_candidates[1] == "cpe:2.3:a:facebook:react:17.0.2:*:*:*:*:*:*:*"


def test_inventory_sorting():
    # CDN, Framework, CMS, Runtime sorting
    fp_cdn = TechnologyFingerprint(
        name="cloudflare",
        version=None,
        category=TechnologyCategory.CDN,
        confidence=80,
        evidence_count=1,
        raw_match_count=1,
        version_status=DetectionStatus.UNKNOWN
    )
    fp_cms = TechnologyFingerprint(
        name="wordpress",
        version="6.2",
        category=TechnologyCategory.CMS,
        confidence=90,
        evidence_count=2,
        raw_match_count=2,
        version_status=DetectionStatus.VERIFIED
    )
    fp_fw = TechnologyFingerprint(
        name="nextjs",
        version="13.4.0",
        category=TechnologyCategory.FRAMEWORK,
        confidence=95,
        evidence_count=3,
        raw_match_count=3,
        version_status=DetectionStatus.VERIFIED
    )
    fp_rt = TechnologyFingerprint(
        name="php",
        version="8.1.0",
        category=TechnologyCategory.RUNTIME,
        confidence=85,
        evidence_count=2,
        raw_match_count=2,
        version_status=DetectionStatus.VERIFIED
    )
    
    wa = WebsiteAssessment(
        url="https://example.com",
        technologies=[fp_cdn, fp_cms, fp_fw, fp_rt],
        security_headers=[]
    )
    
    service = TechnologyInventoryService()
    inventory = service.build_inventory(wa)
    
    # Expected ordering: Framework -> CMS -> Runtime -> CDN
    assert len(inventory) == 4
    assert inventory[0].category == TechnologyCategory.FRAMEWORK # Next.js
    assert inventory[1].category == TechnologyCategory.CMS       # WordPress
    assert inventory[2].category == TechnologyCategory.RUNTIME   # PHP
    assert inventory[3].category == TechnologyCategory.CDN       # Cloudflare
