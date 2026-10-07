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
from pulse.website.acquisition import fetch_observation, validate_url, WebsiteURLPolicyError

import logging
from urllib.parse import urljoin
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


class WebsiteFingerprintAnalyzer:
    """Analyzes web assets passively for technologies and security headers."""

    def __init__(self):
        self.technologies: List[TechnologyFingerprint] = []
        self.security_headers: List[SecurityHeaderStatus] = []

    def scan(self, url: str) -> WebsiteAssessment:
        self.technologies = []
        self.security_headers = []
        warnings = []
        url = url.strip() if isinstance(url, str) else url
        from pulse.state import AppState
        if AppState.OFFLINE_MODE:
            return WebsiteAssessment(url=url, status="OFFLINE", status_code=0,
                                     warnings=["Website acquisition is unavailable in offline mode"])
        ext_only = get_setting("EXTERNAL_ONLY", "false").lower() in ("true", "1", "yes")
        is_valid, err_msg = validate_url(url, external_only=ext_only)
        if not is_valid:
            logger.warning(f"Aborting website scan: {err_msg}")
            return WebsiteAssessment(
                url=url,
                status="INVALID",
                status_code=0,
                warnings=[err_msg],
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
            response = fetch_observation(url, timeout=TIMEOUT, max_bytes=MAX_BODY_SIZE, headers=headers, external_only=ext_only)
            response_headers = response.headers
            cookies = dict(response.cookies)
            body = response.text
            url = str(response.url)
            if response.extensions.get("pulse_body_limit_reached"):
                warnings.append("Website response reached the download limit; evidence may be incomplete")
            if response.status_code >= 400:
                warnings.append(f"Website returned HTTP {response.status_code}; evidence may be incomplete")
        except WebsiteURLPolicyError as exc:
            return WebsiteAssessment(url=url, status="INVALID", status_code=0, warnings=[str(exc)])
        except (httpx.HTTPError, httpx.InvalidURL) as exc:
            return WebsiteAssessment(url=url, status="ERROR", status_code=0,
                                     warnings=[{
                                         "ConnectError": "Could not connect to the website. Check the hostname, TLS certificate, and network connection.",
                                         "ConnectTimeout": "Connection timed out. Check the website is reachable and retry.",
                                         "ReadTimeout": "The website took too long to respond. Retry the scan.",
                                         "TooManyRedirects": "The website exceeded the redirect limit. Check the URL and redirect configuration.",
                                     }.get(type(exc).__name__, f"Website request failed ({type(exc).__name__}). Check the URL and retry.")])
            
        script_srcs = []
        if body:
            script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', body, re.IGNORECASE)

        # 1. Load signatures
        try:
            signatures = SignatureRegistry.load()
        except Exception as exc:
            signatures = []
            warnings.append("Built-in technology signatures could not be loaded; detection is incomplete")
            logger.warning("Signature loading failed: %s", exc)
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
                warnings.append(f"Technology signature {signature.signature_id} failed; detection is incomplete")
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
                if not dfp.cpe_candidates:
                    cpe_val = getattr(dfp, "cpe", None)
                    if cpe_val:
                        dfp.cpe_candidates = [CPECandidate(cpe=cpe_val, confidence=dfp.confidence)]
                dfp.confidence_band = get_confidence_band(dfp.confidence)
                detected_fingerprints.append(dfp)
        except Exception as e:
            warnings.append("Declarative technology detection failed; website evidence may be incomplete")
            logger.warning("Declarative web signature engine execution failed: %s", e)

        # 2.6 Favicon Fingerprinting (Hash Matching)
        try:
            favicon_url = urljoin(url, "/favicon.ico")
            fav_resp = fetch_observation(favicon_url, timeout=3.0, max_bytes=MAX_BODY_SIZE, headers=headers, external_only=ext_only)
            if fav_resp.status_code == 200 and fav_resp.content:
                fav_fp = FaviconFingerprinter.identify(fav_resp.content)
                if fav_fp:
                    fav_cpe = getattr(fav_fp, "cpe", None)
                    if fav_cpe:
                        fav_fp.cpe_candidates = [CPECandidate(cpe=fav_cpe, confidence=100)]
                    fav_fp.confidence_band = get_confidence_band(100)
                    detected_fingerprints.append(fav_fp)
        except WebsiteURLPolicyError as exc:
            warnings.append(str(exc))
        except Exception:
            pass

        # 2.7 Error Page Fingerprinting (404 Probe)
        # Many servers reveal their identity on error pages even when they strip headers
        try:
            import hashlib
            probe_path = f"/pulse-probe-{hashlib.md5(url.encode()).hexdigest()[:8]}"
            probe_url = urljoin(url, probe_path)
            probe_resp = fetch_observation(probe_url, timeout=5.0, max_bytes=50000, headers=headers, follow_redirects=False, external_only=ext_only)
            error_body = probe_resp.text[:50000] if probe_resp.text else ""
            error_headers = dict(probe_resp.headers)

            # Check error page headers (some servers expose identity only on error pages)
            error_server = error_headers.get("Server", "") or error_headers.get("server", "")
            if error_server and not response_headers.get("Server", ""):
                # Server header only appears on error pages -- use it
                if "nginx" in error_server.lower():
                    ver_m = re.search(r'nginx/([0-9.]+)', error_server, re.IGNORECASE)
                    detected_fingerprints.append(TechnologyFingerprint(
                        name="nginx", version=ver_m.group(1) if ver_m else None,
                        category="Server", confidence=90,
                        confidence_band=get_confidence_band(90),
                        evidence_count=1, evidence=[DetectionEvidence(
                            method=DetectionMethod.HEADER, source="Server (404)",
                            value=error_server, confidence=90,
                            description="Server header revealed on error page",
                            reliability=EvidenceReliability.HIGH
                        )]
                    ))
                elif "apache" in error_server.lower():
                    ver_m = re.search(r'Apache/([0-9.]+)', error_server, re.IGNORECASE)
                    detected_fingerprints.append(TechnologyFingerprint(
                        name="Apache HTTP Server", version=ver_m.group(1) if ver_m else None,
                        category="Server", confidence=90,
                        confidence_band=get_confidence_band(90),
                        evidence_count=1, evidence=[DetectionEvidence(
                            method=DetectionMethod.HEADER, source="Server (404)",
                            value=error_server, confidence=90,
                            description="Server header revealed on error page",
                            reliability=EvidenceReliability.HIGH
                        )]
                    ))

            # Check error page body content
            _ERROR_PAGE_PATTERNS = [
                (r'<address>Apache/([0-9.]+)', "Apache HTTP Server", 95),
                (r'<center>nginx/([0-9.]+)</center>', "nginx", 95),
                (r'<center>nginx</center>', "nginx", 85),
                (r'Microsoft-IIS/([0-9.]+)', "Microsoft IIS", 95),
                (r'<h1>It works!</h1>', "Apache HTTP Server", 60),
                (r'Cannot GET /', "Express.js", 75),
                (r'Whitelabel Error Page', "Spring Boot", 90),
                (r'<title>Problem loading page</title>', "Firefox Error", 50),
                (r'<h1 class="text-muted">Page not found</h1>', "Django", 80),
                (r'The page you were looking for doesn.*t exist', "Ruby on Rails", 70),
                (r'<p class="headline">The page you were looking for', "Ruby on Rails", 75),
                (r'Powered by.*<a href="https?://expressjs\.com', "Express.js", 90),
                (r'Apache Tomcat/([0-9.]+)', "Apache Tomcat", 95),
                (r'<h3>Apache Tomcat', "Apache Tomcat", 90),
                (r'<title>404 Not Found</title>.*openresty', "OpenResty", 90),
                (r'openresty/([0-9.]+)', "OpenResty", 95),
                (r'<address>LiteSpeed</address>', "LiteSpeed", 90),
                (r'litespeed', "LiteSpeed", 70),
                (r'Caddy', "Caddy", 65),
            ]
            for pattern, tech_name, conf in _ERROR_PAGE_PATTERNS:
                m = re.search(pattern, error_body, re.IGNORECASE | re.DOTALL)
                if m:
                    ver = m.group(1) if m.lastindex and m.lastindex >= 1 else None
                    detected_fingerprints.append(TechnologyFingerprint(
                        name=tech_name, version=ver,
                        category="Server", confidence=conf,
                        confidence_band=get_confidence_band(conf),
                        evidence_count=1, evidence=[DetectionEvidence(
                            method=DetectionMethod.HTML, source="Error Page Body",
                            value=m.group(0)[:150], confidence=conf,
                            description=f"Technology signature found on 404 error page",
                            reliability=EvidenceReliability.MEDIUM
                        )]
                    ))
        except WebsiteURLPolicyError as exc:
            warnings.append(str(exc))
        except Exception:
            pass

        # 2.8 robots.txt Analysis
        # Detects CMS and platform technologies from robots.txt directives
        try:
            robots_url = urljoin(url, "/robots.txt")
            robots_resp = fetch_observation(robots_url, timeout=3.0, max_bytes=20000, headers=headers, external_only=ext_only)
            if robots_resp.status_code == 200 and robots_resp.text:
                robots_text = robots_resp.text[:20000]  # Limit to 20KB

                _ROBOTS_PATTERNS = [
                    (r'Disallow:\s*/wp-admin', "WordPress", 95),
                    (r'Disallow:\s*/wp-includes', "WordPress", 95),
                    (r'Sitemap:.*sitemap_index\.xml', "WordPress", 80),
                    (r'Disallow:\s*/administrator/', "Joomla", 90),
                    (r'Disallow:\s*/component/', "Joomla", 75),
                    (r'Disallow:\s*/admin/', "Admin Panel", 50),
                    (r'Disallow:\s*/core/', "Drupal", 70),
                    (r'Disallow:\s*/node/', "Drupal", 65),
                    (r'Disallow:\s*/user/', "Drupal", 60),
                    (r'Disallow:\s*/profiles/', "Drupal", 80),
                    (r'Disallow:\s*/includes/', "Drupal", 60),
                    (r'Sitemap:.*sitemap\.xml', "XML Sitemap", 70),
                    (r'Disallow:\s*/ghost/', "Ghost", 85),
                    (r'Disallow:\s*/typo3/', "TYPO3", 90),
                    (r'Disallow:\s*/umbraco/', "Umbraco", 90),
                    (r'Disallow:\s*/sitecore/', "Sitecore", 90),
                    (r'Disallow:\s*/kentico/', "Kentico", 90),
                    (r'Disallow:\s*/magento/', "Magento", 90),
                    (r'Disallow:\s*/checkout/', "E-commerce Platform", 50),
                    (r'Disallow:\s*/cart/', "E-commerce Platform", 50),
                    (r'Disallow:\s*/_next/', "Next.js", 85),
                ]
                for pattern, tech_name, conf in _ROBOTS_PATTERNS:
                    m = re.search(pattern, robots_text, re.IGNORECASE)
                    if m:
                        detected_fingerprints.append(TechnologyFingerprint(
                            name=tech_name, version=None,
                            category="CMS" if tech_name not in ("Next.js", "Admin Panel", "E-commerce Platform", "XML Sitemap") else "Web Technology",
                            confidence=conf,
                            confidence_band=get_confidence_band(conf),
                            evidence_count=1, evidence=[DetectionEvidence(
                                method=DetectionMethod.HTML, source="robots.txt",
                                value=m.group(0).strip()[:100], confidence=conf,
                                description=f"Technology indicator found in robots.txt",
                                reliability=EvidenceReliability.MEDIUM
                            )]
                        ))
        except WebsiteURLPolicyError as exc:
            warnings.append(str(exc))
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
            statistics=stats,
            status="PARTIAL" if warnings else "OK",
            status_code=response.status_code,
            warnings=warnings
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
        headers = httpx.Headers(headers)
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
        
        guidance = {
            "Content-Security-Policy": "Define allowed content sources; test a policy for this application.",
            "Strict-Transport-Security": "For HTTPS sites, configure a positive max-age after verifying HTTPS coverage.",
            "X-Frame-Options": "Review framing protection with DENY, SAMEORIGIN, or CSP frame-ancestors.",
            "Referrer-Policy": "Choose a policy that limits referrer information sent to other origins.",
            "Permissions-Policy": "Restrict browser features that this application does not need.",
            "X-Content-Type-Options": "Set nosniff to prevent MIME type guessing.",
            "Cross-Origin-Opener-Policy": "Review cross-origin window isolation for this application's integrations.",
            "Cross-Origin-Resource-Policy": "Review which origins should be allowed to load these resources.",
        }
        for header, default_status in checks:
            value = headers.get(header)
            if value:
                status = "Present"
                if header == "Content-Security-Policy" and "unsafe-inline" in value:
                    status = "Weak"
                if header == "X-Content-Type-Options" and value.strip().lower() != "nosniff":
                    status = "Misconfigured"
                if header == "X-Frame-Options" and value.strip().upper() not in ("DENY", "SAMEORIGIN"):
                    status = "Misconfigured"
                if header == "Strict-Transport-Security":
                    max_age = re.search(r"(?:^|;)\s*max-age\s*=\s*([0-9]+)\s*(?:;|$)", value, re.IGNORECASE)
                    if not max_age or not max_age.group(1).strip("0"):
                        status = "Weak"
                details = value[:100] + "..." if len(value) > 100 else value
                if status != "Present":
                    details += " — " + guidance[header]
            else:
                status = default_status
                details = "Header is not set. " + guidance[header]
                
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
            "angularjs": "AngularJS",
            "angular.js": "AngularJS",
            "jquery": "jQuery",
            "jquery-migrate": "jQuery Migrate",
            "jquery migrate": "jQuery Migrate",
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
                # Combine evidence
                existing.evidence.extend(t.evidence)
                existing.evidence_count = len(existing.evidence)
                # Combine confidence
                existing.confidence = min(100, max(existing.confidence, t.confidence))
                existing.confidence_band = get_confidence_band(existing.confidence)
                # Prefer versioned detection
                if t.version and not existing.version:
                    existing.version = t.version
                    existing.version_status = t.version_status
                    existing.version_confidence = t.version_confidence
                    existing.version_evidence = t.version_evidence
                # Prefer populated CPEs
                if t.cpe_candidates and not existing.cpe_candidates:
                    existing.cpe_candidates = t.cpe_candidates
                existing.name = canon_name

        # Ensure all versioned technologies have version reflected in CPE candidate strings
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
