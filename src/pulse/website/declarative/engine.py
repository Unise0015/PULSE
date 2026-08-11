"""
Declarative Technology Engine for PULSE Web Subsystem.
Orchestrates pre-filtered index searching, evidence collection, version extraction,
confidence calculation, and implication resolution.
"""

import re
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from pulse.website.declarative.models import (
    DeclarativeEvidence, TechnologyRule, PatternRule
)
from pulse.website.declarative.loader import SignatureLoader
from pulse.website.declarative.index import SignatureIndex
from pulse.website.declarative.matcher import PatternMatcher
from pulse.website.declarative.implications import ImplicationResolver
from pulse.domain.models import (
    TechnologyFingerprint, CPECandidate, DetectionStatus, ConfidenceBand
)
from pulse.website.confidence import get_confidence_band

logger = logging.getLogger(__name__)

MAX_BODY_SIZE = 2 * 1024 * 1024  # 2 MB max body size for analysis protection


class DeclarativeTechnologyEngine:
    """Production-ready declarative technology detection engine."""

    def __init__(self, signatures_dir: Optional[Path] = None):
        self.loader = SignatureLoader(signatures_dir)
        self.index = SignatureIndex(self.loader.technology_rules)

    def detect(
        self,
        url: str,
        headers: Dict[str, str],
        cookies: Dict[str, str],
        html_body: str,
        script_urls: Optional[List[str]] = None
    ) -> List[TechnologyFingerprint]:
        """
        Executes fast, pre-filtered technology detection against HTTP acquisition data.
        
        Returns:
            List of TechnologyFingerprint objects with confidence scores, evidence, and CPEs.
        """
        # Truncate HTML body safely if larger than MAX_BODY_SIZE
        if html_body and len(html_body) > MAX_BODY_SIZE:
            logger.warning("Truncating HTML body from %d bytes to MAX_BODY_SIZE (%d bytes) for safety.", len(html_body), MAX_BODY_SIZE)
            html_body = html_body[:MAX_BODY_SIZE]

        # Case-insensitive header dictionary normalization
        normalized_headers = {k.lower().strip(): v for k, v in headers.items()}
        normalized_cookies = {k.lower().strip(): v for k, v in cookies.items()}

        detected_map: Dict[str, Dict[str, Any]] = {}  # tech_name -> detected metadata

        def record_detection(
            tech_name: str,
            rule: PatternRule,
            evidence: DeclarativeEvidence,
            version: Optional[str]
        ):
            tech_rule = self.loader.technology_rules.get(tech_name)
            categories = tech_rule.categories if tech_rule else ["Web Technology"]
            cpes = tech_rule.cpes if tech_rule else []

            if tech_name not in detected_map:
                detected_map[tech_name] = {
                    "confidence": rule.confidence,
                    "version": version,
                    "category": categories[0] if categories else "Web Technology",
                    "cpes": cpes,
                    "evidence": [evidence],
                    "inferred": False,
                    "inferred_from": None
                }
            else:
                existing = detected_map[tech_name]
                # Combined bounded confidence formula: min(100, base + increment)
                existing["confidence"] = min(100, existing["confidence"] + (rule.confidence // 2))
                existing["evidence"].append(evidence)
                if not existing["version"] and version:
                    existing["version"] = version
                if not existing["cpes"] and cpes:
                    existing["cpes"] = cpes

        # 1. Match Headers
        for h_key, h_val in normalized_headers.items():
            if h_key in self.index.headers:
                for tech_name, rule in self.index.headers[h_key]:
                    result = PatternMatcher.match_rule(rule, h_val, source="header", header_name=h_key)
                    if result:
                        ev, ver = result
                        record_detection(tech_name, rule, ev, ver)

        # 2. Match Cookies
        for c_key, c_val in normalized_cookies.items():
            if c_key in self.index.cookies:
                for tech_name, rule in self.index.cookies[c_key]:
                    result = PatternMatcher.match_rule(rule, c_val, source="cookie", cookie_name=c_key)
                    if result:
                        ev, ver = result
                        record_detection(tech_name, rule, ev, ver)

        # 3. Match Script URLs
        if script_urls:
            script_blob = "\n".join(script_urls)
            for tech_name, rule in self.index.script_src_rules:
                result = PatternMatcher.match_rule(rule, script_blob, source="script")
                if result:
                    ev, ver = result
                    record_detection(tech_name, rule, ev, ver)

        # 4. Match Meta Tags
        if html_body and ("meta" in html_body.lower() or "generator" in html_body.lower()):
            meta_matches = re.findall(r'<meta\s+name=["\']([^"\']+)["\']\s+content=["\']([^"\']+)["\']', html_body, re.IGNORECASE)
            for m_name, m_val in meta_matches:
                m_key = m_name.lower().strip()
                if m_key in self.index.meta:
                    for tech_name, rule in self.index.meta[m_key]:
                        result = PatternMatcher.match_rule(rule, m_val, source="meta", meta_name=m_name)
                        if result:
                            ev, ver = result
                            record_detection(tech_name, rule, ev, ver)

        # 5. Match HTML Body
        if html_body:
            for tech_name, rule in self.index.html_rules:
                result = PatternMatcher.match_rule(rule, html_body, source="html")
                if result:
                    ev, ver = result
                    record_detection(tech_name, rule, ev, ver)


        # 6. Implication Graph & Exclusion Resolution
        resolved_map = ImplicationResolver.resolve(detected_map, self.loader.technology_rules)

        # 7. Construct TechnologyFingerprint objects
        fingerprints: List[TechnologyFingerprint] = []

        for name, data in resolved_map.items():
            # Build CPE Candidates
            cpe_cands = []
            version_str = data.get("version")
            cpe_list = data.get("cpes", [])

            for cpe_base in cpe_list:
                if cpe_base:
                    # Substitute version into CPE string if template format
                    final_cpe = cpe_base
                    if version_str and ":*:" in cpe_base:
                        parts = cpe_base.split(":")
                        if len(parts) >= 5:
                            final_cpe = f"cpe:2.3:a:{parts[3]}:{parts[4]}:{version_str}:*:*:*:*:*:*:*"
                    cpe_cands.append(CPECandidate(cpe=final_cpe, confidence=data["confidence"]))

            # Convert evidence to domain model evidence
            domain_ev_list = [ev.to_domain_evidence() for ev in data.get("evidence", [])]
            version_status = DetectionStatus.VERIFIED if version_str else DetectionStatus.UNKNOWN
            rule_obj = self.loader.technology_rules.get(name)
            
            rule_domain = rule_obj.domain if rule_obj else "web"
            rule_vendor = rule_obj.vendor if rule_obj else None
            is_inferred = data.get("inferred", False)

            if version_str and cpe_cands:
                vuln_stat = "EXACT"
            elif cpe_cands:
                vuln_stat = "PARTIAL"
            else:
                vuln_stat = "UNRESOLVED"

            fp = TechnologyFingerprint(
                name=name,
                version=version_str,
                category=data["category"],
                confidence=data["confidence"],
                confidence_band=get_confidence_band(data["confidence"]),
                evidence_count=len(domain_ev_list),
                version_status=version_status,
                evidence=domain_ev_list,
                cpe_candidates=cpe_cands,
                parent=data.get("inferred_from"),
                vendor=rule_vendor,
                domain=rule_domain,
                direct_detection=not is_inferred,
                inferred=is_inferred,
                vulnerability_status=vuln_stat
            )
            fingerprints.append(fp)

        return fingerprints

