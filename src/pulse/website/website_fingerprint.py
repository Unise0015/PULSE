import re
import time
import httpx
from typing import List, Dict, Optional, Tuple
from pulse.domain.models import (
    WebsiteAssessment, TechnologyFingerprint, SecurityHeaderStatus,
    FingerprintStatistics, SignatureExecutionMetrics, DetectionEvidence,
    DetectionMethod, DetectionStatus, ConfidenceBand, EvidenceReliability,
    CPECandidate
)
from pulse.website.signatures import SignatureRegistry
from pulse.website.confidence import WeightedMaxBonusCalculator, get_confidence_band, SignalDisagreementDetector
from pulse.website.declarative_engine import DeclarativeSignatureEngine
from pulse.website.favicon_fingerprint import FaviconFingerprinter
from pulse.website.bot_challenge import BotChallengeDetector

import ipaddress
import logging
from urllib.parse import urlparse, urljoin
from pulse.config import get_setting

logger = logging.getLogger(__name__)

MAX_BODY_SIZE = 2 * 1024 * 1024  # 2 MB
TIMEOUT = 10.0
MAX_REDIRECTS = 5

_DECLARATIVE_ENGINE: Optional[DeclarativeSignatureEngine] = None

def get_declarative_engine() -> DeclarativeSignatureEngine:
    global _DECLARATIVE_ENGINE
    if _DECLARATIVE_ENGINE is None:
        _DECLARATIVE_ENGINE = DeclarativeSignatureEngine()
    return _DECLARATIVE_ENGINE


def validate_url(url: str, external_only: bool = False) -> Tuple[bool, str]:
    """Pre-request URL validator. Rejects malformed URLs and unsupported protocols."""
    if not url or not isinstance(url, str) or not url.strip():
        return False, "Invalid URL: Empty target string provided"

    raw_url = url.strip()
    try:
        parsed = urlparse(raw_url)
    except Exception as e:
        return False, f"Invalid URL structure: {e}"

    if not parsed.scheme or parsed.scheme.lower() not in ("http", "https"):
        return False, f"Invalid URL scheme '{parsed.scheme}'. Only http:// and https:// protocols are supported."

    hostname = parsed.hostname
    if not hostname:
        return False, "Invalid URL: Missing hostname or domain"

    if external_only:
        if hostname.lower() in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
            return False, f"External-only policy enforced: Target '{hostname}' is localhost/loopback"

        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                return False, f"External-only policy enforced: Target '{hostname}' is a private or internal IP"
        except ValueError:
            pass

    return True, "URL is valid"


class WebsiteFingerprintAnalyzer:
    """Analyzes web assets passively across 6+ signal vectors, multi-route probing, and SRI hashing."""

    def __init__(self):
        self.technologies: List[TechnologyFingerprint] = []
        self.security_headers: List[SecurityHeaderStatus] = []

    def scan(self, url: str) -> WebsiteAssessment:
        ext_only = get_setting("EXTERNAL_ONLY", "false").lower() in ("true", "1", "yes")
        is_valid, err_msg = validate_url(url, external_only=ext_only)
        if not is_valid:
            logger.warning(f"Aborting website scan: {err_msg}")
            return WebsiteAssessment(
                url=url,
                status="INVALID",
                status_code=0,
                technologies=[],
                security_headers=[]
            )

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 PULSE/1.0"
        }
        
        body = ""
        response_headers = {}
        cookies = {}
        status_code = 200
        
        try:
            with httpx.Client(timeout=TIMEOUT, follow_redirects=True, max_redirects=MAX_REDIRECTS) as client:
                with client.stream("GET", url, headers=headers) as response:
                    status_code = response.status_code
                    response_headers = dict(response.headers)
                    cookies = dict(response.cookies)
                    
                    bytes_read = 0
                    chunks = []
                    for chunk in response.iter_bytes(chunk_size=8192):
                        bytes_read += len(chunk)
                        if bytes_read > MAX_BODY_SIZE:
                            chunks.append(chunk[:len(chunk) - (bytes_read - MAX_BODY_SIZE)])
                            break
                        chunks.append(chunk)
                        
                    body = b"".join(chunks).decode('utf-8', errors='ignore')
        except Exception as e:
            logger.debug("Primary HTTP request failed for %s: %s", url, e)

        # 0. Bot-Challenge & WAF Interstitial Check
        challenge_check = BotChallengeDetector.inspect(status_code, response_headers, body)
        if challenge_check.is_challenge:
            logger.warning("Bot challenge screen detected: %s", challenge_check.reason)

        script_srcs = []
        if body:
            script_srcs = re.findall(r"""<script[^>]+src=["']([^"']+)["']""", body, re.IGNORECASE)

        # 1. Load Procedural Signatures
        signatures = SignatureRegistry.load()
        execution_metrics: List[SignatureExecutionMetrics] = []
        detected_fingerprints: List[TechnologyFingerprint] = []
        
        signatures_matched = 0
        total_evidence_items = 0
        calculator = WeightedMaxBonusCalculator()

        # 2. Execute Procedural Signatures
        for signature in signatures:
            t0 = time.perf_counter()
            try:
                raw_evidence = signature.match(response_headers, body, cookies, script_srcs)
            except Exception:
                raw_evidence = []
            t1 = time.perf_counter()
            execution_time_ms = (t1 - t0) * 1000.0

            unique_evidence = self._deduplicate_evidence(raw_evidence)
            is_matched = len(unique_evidence) >= signature.minimum_matches
            match_rate = SignatureRegistry.record_execution(signature.signature_id, is_matched)
            
            execution_metrics.append(SignatureExecutionMetrics(
                signature_id=signature.signature_id,
                execution_time_ms=execution_time_ms,
                evidence_generated=len(raw_evidence),
                technologies_detected=1 if is_matched else 0,
                match_rate=match_rate
            ))
            
            if is_matched:
                signatures_matched += 1
                total_evidence_items += len(unique_evidence)
                
                version = None
                if signature.provides_version:
                    try:
                        version = signature.extract_version(response_headers, body, cookies, script_srcs)
                    except Exception:
                        pass
                
                version_status, version_confidence, version_evidence = self._determine_version_info(version, unique_evidence)
                confidence_score = calculator.calculate(unique_evidence)
                confidence_band = get_confidence_band(confidence_score)
                
                cpe_candidates = []
                if signature.provides_cpe_candidates:
                    try:
                        cpe_candidates = signature.get_cpe_candidates(version)
                    except Exception:
                        pass
                
                detected_fingerprints.append(TechnologyFingerprint(
                    name=signature.name,
                    version=version,
                    category=signature.category,
                    confidence=confidence_score,
                    confidence_band=confidence_band,
                    evidence_count=len(unique_evidence),
                    raw_match_count=len(raw_evidence),
                    version_status=version_status,
                    evidence=unique_evidence,
                    version_evidence=version_evidence,
                    version_confidence=version_confidence,
                    signature_id=signature.signature_id,
                    signature_version=signature.signature_version,
                    cpe_candidates=cpe_candidates,
                    ecosystem=signature.ecosystem,
                    correlation_supported=signature.correlation_supported,
                    parent=None,
                    children=[]
                ))

        # 2.5 Declarative Signature Engine Execution (3,000+ Declarative JSON Signatures + SRI)
        try:
            decl_engine = get_declarative_engine()
            decl_fingerprints = decl_engine.detect(
                url=url,
                headers=response_headers,
                cookies=cookies,
                html_body=body,
                script_urls=script_srcs
            )
            for dfp in decl_fingerprints:
                if not dfp.cpe_candidates:
                    cpe_val = getattr(dfp, "cpe", None)
                    if cpe_val:
                        dfp.cpe_candidates = [CPECandidate(cpe=cpe_val, confidence=dfp.confidence)]
                dfp.confidence_band = get_confidence_band(dfp.confidence)
                detected_fingerprints.append(dfp)
        except Exception as e:
            logger.warning("Declarative web signature engine execution failed: %s", e)

        # 2.6 Multi-Route Probing (robots.txt, wp-json, and synthetic 404 error debug screen probe)
        if not challenge_check.is_challenge:
            try:
                self._probe_auxiliary_routes(url, decl_engine, detected_fingerprints)
            except Exception as e:
                logger.debug("Auxiliary route probing error: %s", e)

        # 2.7 Favicon Fingerprinting (Cryptographic MurmurHash3 MMH3 Matching)
        try:
            favicon_url = urljoin(url, "/favicon.ico")
            with httpx.Client(timeout=3.0, follow_redirects=True) as fav_client:
                fav_resp = fav_client.get(favicon_url)
                if fav_resp.status_code == 200 and fav_resp.content:
                    fav_fp = FaviconFingerprinter.identify(fav_resp.content)
                    if fav_fp:
                        fav_cpe = getattr(fav_fp, "cpe", None)
                        if fav_cpe:
                            fav_fp.cpe_candidates = [CPECandidate(cpe=fav_cpe, confidence=100)]
                        fav_fp.confidence_band = get_confidence_band(100)
                        detected_fingerprints.append(fav_fp)
        except Exception:
            pass

        # 3. Deduplicate final list of technologies by name
        final_techs = self._deduplicate(detected_fingerprints)

        # 4. Establish relationships
        tech_map = {f.signature_id: f for f in final_techs if f.signature_id}
        for fp in final_techs:
            sig_conf = next((s for s in signatures if s.signature_id == fp.signature_id), None)
            if sig_conf and sig_conf.supports_relationships and sig_conf.parent_id:
                parent_fp = tech_map.get(sig_conf.parent_id)
                if parent_fp:
                    fp.parent = parent_fp.name
                    if fp.name not in parent_fp.children:
                        parent_fp.children.append(fp.name)

        # 5. Validate DAG to avoid cycles
        try:
            self._validate_dag(final_techs)
        except ValueError as e:
            logger.error(f"DAG Validation failed: {e}")

        # 6. Assess Security Headers
        self._assess_security_headers(response_headers)
        
        # 7. Collect Statistics
        stats = FingerprintStatistics(
            signatures_loaded=len(signatures),
            signatures_matched=signatures_matched,
            evidence_items=total_evidence_items,
            technologies_detected=len(final_techs),
            execution_metrics=execution_metrics
        )

        return WebsiteAssessment(
            url=url,
            technologies=final_techs,
            security_headers=self.security_headers,
            statistics=stats
        )

    def _probe_auxiliary_routes(
        self,
        base_url: str,
        decl_engine: DeclarativeSignatureEngine,
        detected_fingerprints: List[TechnologyFingerprint]
    ):
        """Passively probes robots.txt and synthetic error page for unhardened debug traces."""
        routes_to_probe = [
            "/robots.txt",
            "/_pulse_probe_error_404_"
        ]
        with httpx.Client(timeout=2.5, follow_redirects=True) as probe_client:
            for route in routes_to_probe:
                try:
                    probe_url = urljoin(base_url, route)
                    resp = probe_client.get(probe_url, headers={"User-Agent": "PULSE/1.0"})
                    if resp.status_code in (200, 404, 500) and resp.text:
                        # Feed response through declarative engine to catch Whoops / YSOD / Spring Whitelabel
                        route_fps = decl_engine.detect(
                            url=probe_url,
                            headers=dict(resp.headers),
                            cookies=dict(resp.cookies),
                            html_body=resp.text[:65536]
                        )
                        for rfp in route_fps:
                            rfp.confidence_band = get_confidence_band(rfp.confidence)
                            detected_fingerprints.append(rfp)
                except Exception:
                    continue

    def _deduplicate_evidence(self, evidence: List[DetectionEvidence]) -> List[DetectionEvidence]:
        seen = {}
        for ev in evidence:
            key = (ev.method, ev.source, ev.value)
            if key not in seen:
                seen[key] = ev
            else:
                if ev.confidence > seen[key].confidence:
                    seen[key] = ev
        return list(seen.values())

    def _determine_version_info(self, version: Optional[str], evidence: List[DetectionEvidence]) -> Tuple[DetectionStatus, int, Optional[DetectionEvidence]]:
        if not version:
            return DetectionStatus.UNKNOWN, 0, None
            
        version_lower = version.lower()
        for ev in evidence:
            if version_lower in ev.value.lower() or version_lower in ev.description.lower():
                if ev.method == DetectionMethod.HEADER:
                    return DetectionStatus.VERIFIED, 100, ev
                elif ev.method == DetectionMethod.META or "generator" in ev.description.lower() or "ng-version" in ev.description.lower():
                    return DetectionStatus.VERIFIED, 90, ev
                elif ev.method == DetectionMethod.SCRIPT:
                    return DetectionStatus.VERIFIED, 80, ev
                elif ev.method == DetectionMethod.HTML:
                    return DetectionStatus.VERIFIED, 80, ev
                elif ev.method == DetectionMethod.COOKIE:
                    return DetectionStatus.VERIFIED, 80, ev
                    
        return DetectionStatus.ESTIMATED, 50, None

    def _validate_dag(self, fingerprints: List[TechnologyFingerprint]):
        tech_map = {f.name: f for f in fingerprints}
        visited = set()
        path = set()
        
        def dfs(name: str, depth: int):
            if depth > 10:
                raise ValueError(f"Max tree depth (10) exceeded at technology {name}")
            if name in path:
                raise ValueError(f"Circular dependency cycle detected: {' -> '.join(list(path) + [name])}")
            if name in visited:
                return
                
            path.add(name)
            fp = tech_map.get(name)
            if fp:
                for child_name in fp.children:
                    dfs(child_name, depth + 1)
            path.remove(name)
            visited.add(name)
            
        for fp in fingerprints:
            if not fp.parent:
                dfs(fp.name, 1)
                
        for fp in fingerprints:
            if fp.name not in visited:
                dfs(fp.name, 1)

    def _assess_security_headers(self, headers: dict):
        checks = [
            ("Content-Security-Policy", "Missing"),
            ("Strict-Transport-Security", "Missing"),
            ("X-Frame-Options", "Missing"),
            ("Referrer-Policy", "Missing"),
            ("Permissions-Policy", "Missing"),
            ("X-Content-Type-Options", "Missing"),
            ("Cross-Origin-Opener-Policy", "Missing"),
            ("Cross-Origin-Resource-Policy", "Missing")
        ]
        
        for header, default_status in checks:
            value = headers.get(header)
            if value:
                status = "Present"
                if header == "Content-Security-Policy" and "unsafe-inline" in value:
                    status = "Weak"
                details = value[:100] + "..." if len(value) > 100 else value
            else:
                status = default_status
                details = "Header is not set."
                
            self.security_headers.append(SecurityHeaderStatus(
                header_name=header,
                status=status,
                details=details
            ))

    def _deduplicate(self, techs: List[TechnologyFingerprint]) -> List[TechnologyFingerprint]:
        """Deduplicate technologies by name, keeping highest confidence/version."""
        alias_map = {
            "apache": "Apache HTTP Server",
            "apache http server": "Apache HTTP Server",
            "tailwind": "Tailwind CSS",
            "tailwindcss": "Tailwind CSS",
            "tailwind css": "Tailwind CSS",
            "next": "Next.js",
            "nextjs": "Next.js",
            "next.js": "Next.js",
            "nuxt": "Nuxt.js",
            "nuxtjs": "Nuxt.js",
            "nuxt.js": "Nuxt.js",
            "vue": "Vue.js",
            "vuejs": "Vue.js",
            "vue.js": "Vue.js",
            "react": "React",
            "reactjs": "React",
            "angular": "Angular",
            "angularjs": "Angular",
            "jquery": "jQuery",
            "jquery-migrate": "jQuery Migrate",
            "jquery migrate": "jQuery Migrate",
            "spring": "Spring Boot",
            "spring boot": "Spring Boot",
            "asp.net": "ASP.NET",
        }

        best: Dict[str, TechnologyFingerprint] = {}
        for t in techs:
            raw_key = t.name.lower().strip()
            canon_name = alias_map.get(raw_key, t.name)
            canon_key = canon_name.lower()

            if canon_key not in best:
                t.name = canon_name
                best[canon_key] = t
            else:
                existing = best[canon_key]
                existing.evidence.extend(t.evidence)
                existing.evidence_count = len(existing.evidence)
                existing.confidence = min(100, max(existing.confidence, t.confidence))
                existing.confidence_band = get_confidence_band(existing.confidence)
                if t.version and not existing.version:
                    existing.version = t.version
                    existing.version_status = t.version_status
                    existing.version_confidence = t.version_confidence
                    existing.version_evidence = t.version_evidence
                if t.cpe_candidates and not existing.cpe_candidates:
                    existing.cpe_candidates = t.cpe_candidates
                existing.name = canon_name

        for fp in best.values():
            if fp.version and fp.cpe_candidates:
                updated_cpes = []
                for cand in fp.cpe_candidates:
                    cpe_str = cand.cpe
                    if ":*:" in cpe_str:
                        parts = cpe_str.split(":")
                        if len(parts) >= 6 and parts[5] in ("*", ""):
                            parts[5] = fp.version
                            cpe_str = ":".join(parts)
                    updated_cpes.append(CPECandidate(cpe=cpe_str, confidence=cand.confidence))
                fp.cpe_candidates = updated_cpes

        return list(best.values())
