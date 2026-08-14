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
from pulse.website.confidence import WeightedMaxBonusCalculator, get_confidence_band
from pulse.website.declarative_engine import DeclarativeSignatureEngine
from pulse.website.favicon_fingerprint import FaviconFingerprinter

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
    """Analyzes web assets passively for technologies and security headers."""

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
        
        try:
            with httpx.Client(timeout=TIMEOUT, follow_redirects=True, max_redirects=MAX_REDIRECTS) as client:
                with client.stream("GET", url, headers=headers) as response:
                    response_headers = dict(response.headers)
                    cookies = dict(response.cookies)
                    
                    # Read up to MAX_BODY_SIZE
                    bytes_read = 0
                    chunks = []
                    for chunk in response.iter_bytes(chunk_size=8192):
                        bytes_read += len(chunk)
                        if bytes_read > MAX_BODY_SIZE:
                            chunks.append(chunk[:len(chunk) - (bytes_read - MAX_BODY_SIZE)])
                            break
                        chunks.append(chunk)
                        
                    body = b"".join(chunks).decode('utf-8', errors='ignore')
        except Exception:
            # Return what we have (empty) if request fails
            pass
            
        script_srcs = []
        if body:
            script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', body, re.IGNORECASE)

        # 1. Load signatures
        signatures = SignatureRegistry.load()
        execution_metrics: List[SignatureExecutionMetrics] = []
        detected_fingerprints: List[TechnologyFingerprint] = []
        
        signatures_matched = 0
        total_evidence_items = 0
        
        calculator = WeightedMaxBonusCalculator()

        # 2. Execute each signature
        for signature in signatures:
            t0 = time.perf_counter()
            try:
                raw_evidence = signature.match(response_headers, body, cookies, script_srcs)
            except Exception:
                raw_evidence = []
            t1 = time.perf_counter()
            execution_time_ms = (t1 - t0) * 1000.0

            # Deduplicate evidence for this signature
            unique_evidence = self._deduplicate_evidence(raw_evidence)
            
            # Check if signature matches
            is_matched = len(unique_evidence) >= signature.minimum_matches
            
            # Record execution and calculate match rate
            match_rate = SignatureRegistry.record_execution(signature.signature_id, is_matched)
            
            # Record metrics
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
                
                # Extract version if supported
                version = None
                if signature.provides_version:
                    try:
                        version = signature.extract_version(response_headers, body, cookies, script_srcs)
                    except Exception:
                        pass
                
                # Determine version status and confidence
                version_status, version_confidence, version_evidence = self._determine_version_info(version, unique_evidence)
                
                # Calculate confidence score
                confidence_score = calculator.calculate(unique_evidence)
                confidence_band = get_confidence_band(confidence_score)
                
                # CPE Candidates
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

        # 2.5 Declarative Signature Engine Execution (3000+ JSON Signatures)
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
                cpe_cands = []
                cpe_val = getattr(dfp, "cpe", None)
                if cpe_val:
                    cpe_cands.append(CPECandidate(cpe=cpe_val, confidence=dfp.confidence))
                dfp.cpe_candidates = cpe_cands
                dfp.confidence_band = get_confidence_band(dfp.confidence)
                detected_fingerprints.append(dfp)
        except Exception as e:
            logger.warning("Declarative web signature engine execution failed: %s", e)

        # 2.6 Favicon Fingerprinting (Hash Matching)
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
            # Find matching signature configuration
            sig_conf = next((s for s in signatures if s.signature_id == fp.signature_id), None)
            if sig_conf and sig_conf.supports_relationships and sig_conf.parent_id:
                parent_fp = tech_map.get(sig_conf.parent_id)
                if parent_fp:
                    fp.parent = parent_fp.name
                    if fp.name not in parent_fp.children:
                        parent_fp.children.append(fp.name)

        # 5. Validate DAG to avoid infinite loops and cycles
        try:
            self._validate_dag(final_techs)
        except ValueError as e:
            # Safely break all relationships if validation fails to keep scan running
            for fp in final_techs:
                fp.parent = None
                fp.children = []

        # 6. Analyze security headers
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
        best: Dict[str, TechnologyFingerprint] = {}
        for t in techs:
            name = t.name.lower()
            if name not in best:
                best[name] = t
            else:
                existing = best[name]
                # Prefer one with a version
                if t.version and not existing.version:
                    best[name] = t
                # Prefer higher confidence if versions are same status
                elif (t.version and existing.version) or (not t.version and not existing.version):
                    if t.confidence > existing.confidence:
                        best[name] = t
        return list(best.values())
