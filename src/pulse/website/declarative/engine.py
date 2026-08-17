"""
Declarative Technology Detection Engine for PULSE.
Evaluates 3,000+ declarative rules across headers, cookies, HTML meta tags,
script/asset URLs, DOM/SSR framework markers (Next.js App Router RSC, Nuxt 3, SvelteKit, Astro,
Laravel, Django, Spring Boot, ASP.NET), and Subresource Integrity (SRI) hashes.
"""

import logging
import re
import json
from typing import Dict, List, Optional, Set, Tuple, Any

from pulse.website.declarative.loader import SignatureLoader
from pulse.website.declarative.matcher import PatternMatcher
from pulse.website.declarative.implications import ImplicationResolver
from pulse.website.declarative.models import (
    TechnologyRule, DeclarativeEvidence, PatternRule
)
from pulse.domain.models import (
    TechnologyFingerprint, TechnologyCategory, CPECandidate,
    DetectionEvidence, DetectionMethod, DetectionStatus, ConfidenceBand
)
from pulse.website.confidence import get_confidence_band
from pulse.website.sri_resolver import SRIResolver, SRIResolution

logger = logging.getLogger(__name__)


class DeclarativeTechnologyEngine:
    """High-performance declarative signature matching engine."""

    def __init__(self, signatures: Optional[List[TechnologyRule]] = None):
        if signatures is not None:
            self.signatures = signatures
            self.signatures_by_name = {s.name: s for s in self.signatures}
        else:
            loader = SignatureLoader()
            self.signatures_by_name = loader.technology_rules
            self.signatures = list(self.signatures_by_name.values())
        self.sri_resolver = SRIResolver()

    def detect(
        self,
        url: str,
        headers: Dict[str, str],
        cookies: Dict[str, str],
        html_body: str = "",
        script_urls: Optional[List[str]] = None
    ) -> List[TechnologyFingerprint]:
        """
        Executes declarative detection across all signal channels and framework markers.
        """
        html = html_body or ""
        detected_map: Dict[str, Dict[str, Any]] = {}
        normalized_headers = {k.lower().strip(): v for k, v in headers.items()}
        
        # 1. Subresource Integrity (SRI) Hash Resolution (Cryptographic 100% Certainty)
        if html and "integrity=" in html:
            try:
                sri_matches = self.sri_resolver.resolve_html(html)
                for sm in sri_matches:
                    tech_name = sm.package_name
                    ev = DetectionEvidence(
                        method=DetectionMethod.SCRIPT,
                        source="sri_hash",
                        value=f"{sm.package_name}@{sm.version} (hash: {sm.hex_hash[:16]}...)",
                        confidence=100,
                        description=f"Cryptographic Subresource Integrity hash match for {sm.package_name}@{sm.version}"
                    )
                    detected_map[tech_name] = {
                        "confidence": 100,
                        "version": sm.version,
                        "category": TechnologyCategory.FRAMEWORK,
                        "cpes": [f"cpe:2.3:a:{tech_name}:{tech_name}:{sm.version}:*:*:*:*:*:*:*"],
                        "evidence": [ev],
                        "inferred": False
                    }
            except Exception as e:
                logger.debug("SRI resolution error: %s", e)

        # 2. Extract Script & Stylesheet URLs from HTML if not provided
        all_scripts: List[str] = list(script_urls) if script_urls else []
        all_stylesheets: List[str] = []
        if html:
            for m in re.finditer(r"""<script[^>]+src=["']([^"']+)["']""", html, re.IGNORECASE):
                all_scripts.append(m.group(1))
            for m in re.finditer(r"""<link[^>]+(?:href=["']([^"']+)["'][^>]+rel=["']stylesheet["']|rel=["']stylesheet["'][^>]+href=["']([^"']+)["'])""", html, re.IGNORECASE):
                href = m.group(1) or m.group(2)
                if href:
                    all_stylesheets.append(href)

        # 3. Extract HTML Meta Tags (Attribute-Order Agnostic)
        meta_tags: List[Tuple[str, str]] = []
        if html:
            for m in re.finditer(r"""<meta\s+([^>]+)>""", html, re.IGNORECASE):
                tag_content = m.group(1)
                name_m = re.search(r"""(?:name|property|http-equiv)=["']([^"']+)["']""", tag_content, re.IGNORECASE)
                content_m = re.search(r"""content=["']([^"']+)["']""", tag_content, re.IGNORECASE)
                if name_m and content_m:
                    meta_tags.append((name_m.group(1).lower().strip(), content_m.group(1).strip()))

        # 4. Tokenize Compound Server & Powered-By Headers
        tokenized_header_values: List[Tuple[str, str, Optional[str]]] = []
        for h_key in ["server", "x-powered-by", "via"]:
            if h_key in normalized_headers:
                raw_val = normalized_headers[h_key]
                tokens = re.split(r'[\s,;]+', raw_val)
                for tok in tokens:
                    tok = tok.strip("()")
                    if "/" in tok:
                        name_part, ver_part = tok.split("/", 1)
                        tokenized_header_values.append((h_key, name_part.strip(), ver_part.strip()))
                    elif tok:
                        tokenized_header_values.append((h_key, tok.strip(), None))

        # 5. Evaluate Declarative Signatures (Headers, Cookies, Meta, Scripts, HTML)
        for sig in self.signatures:
            evidence_list: List[DetectionEvidence] = []
            extracted_versions: List[str] = []

            # 5a. Match Headers
            for header_name, rules in sig.headers.items():
                target_header = header_name.lower().strip()
                if target_header in normalized_headers:
                    header_val = normalized_headers[target_header]
                    for rule in rules:
                        res = PatternMatcher.match_rule(rule, header_val, "header", header_name=header_name)
                        if res:
                            ev, ver = res
                            evidence_list.append(ev.to_domain_evidence())
                            if ver:
                                extracted_versions.append(ver)

                for orig_h_key, tok_name, tok_ver in tokenized_header_values:
                    if target_header == orig_h_key:
                        for rule in rules:
                            res = PatternMatcher.match_rule(rule, tok_name, "header", header_name=header_name)
                            if res:
                                ev, ver = res
                                final_ver = tok_ver if (tok_ver and not ver) else ver
                                ev.version = final_ver
                                evidence_list.append(ev.to_domain_evidence())
                                if final_ver:
                                    extracted_versions.append(final_ver)

            # 5b. Match Cookies
            for cookie_name, rules in sig.cookies.items():
                for c_key, c_val in cookies.items():
                    if cookie_name.lower() == c_key.lower():
                        for rule in rules:
                            res = PatternMatcher.match_rule(rule, c_val, "cookie", cookie_name=c_key)
                            if res:
                                ev, ver = res
                                evidence_list.append(ev.to_domain_evidence())
                                if ver:
                                    extracted_versions.append(ver)

            # 5c. Match Meta Tags
            for meta_name, rules in sig.meta.items():
                meta_target = meta_name.lower().strip()
                for m_name, m_val in meta_tags:
                    if m_name == meta_target:
                        for rule in rules:
                            res = PatternMatcher.match_rule(rule, m_val, "meta", meta_name=m_name)
                            if res:
                                ev, ver = res
                                evidence_list.append(ev.to_domain_evidence())
                                if ver:
                                    extracted_versions.append(ver)

            # 5d. Match Script & Stylesheet URLs
            if sig.scripts:
                for script_url in all_scripts:
                    for rule in sig.scripts:
                        res = PatternMatcher.match_rule(rule, script_url, "script")
                        if res:
                            ev, ver = res
                            evidence_list.append(ev.to_domain_evidence())
                            if ver:
                                extracted_versions.append(ver)

            # 5e. Match HTML Structural Patterns
            if sig.html and html:
                for rule in sig.html:
                    res = PatternMatcher.match_rule(rule, html, "html")
                    if res:
                        ev, ver = res
                        evidence_list.append(ev.to_domain_evidence())
                        if ver:
                            extracted_versions.append(ver)

            if evidence_list:
                primary_version = PatternMatcher.normalize_version(extracted_versions[0]) if extracted_versions else None
                max_conf = max(e.confidence for e in evidence_list)
                cpe_list = []
                if sig.cpes:
                    for cpe_tmpl in sig.cpes:
                        cpe_list.append(cpe_tmpl.replace("{version}", primary_version if primary_version else "*"))

                cat_val = TechnologyCategory.FRAMEWORK
                if sig.categories:
                    raw_cat = sig.categories[0].upper().replace(" ", "_")
                    for tc in TechnologyCategory:
                        if tc.name == raw_cat or tc.value.lower() == sig.categories[0].lower():
                            cat_val = tc
                            break

                detected_map[sig.name] = {
                    "confidence": max_conf,
                    "version": primary_version,
                    "category": cat_val,
                    "cpes": cpe_list,
                    "evidence": evidence_list,
                    "inferred": False,
                    "domain": sig.domain,
                    "vendor": sig.vendor
                }

        # 6. Advanced Framework AST & Structural State Markers
        if html:
            # 6a. Next.js (App Router RSC + Pages Router)
            if ("__next_f" in html or "self.__next_f.push" in html or "/_next/static/chunks/app/" in html or
                "data-nextjs-scroll-focus-boundary" in html or "__NEXT_DATA__" in html or "/_next/static/" in html):
                next_ver = None
                
                # Check Pages Router __NEXT_DATA__ JSON payload
                nd_match = re.search(r"""<script\s+id="__NEXT_DATA__"[^>]*>(.*?)</script>""", html, re.DOTALL | re.IGNORECASE)
                if nd_match:
                    try:
                        data = json.loads(nd_match.group(1))
                        bid = data.get("buildId", "")
                        bver = re.search(r"(\d+\.\d+\.\d+)", bid)
                        if bver:
                            next_ver = bver.group(1)
                    except Exception:
                        pass

                # Check App Router or asset chunk paths for Next.js version
                if not next_ver:
                    v_match = re.search(r"/_next/static/chunks/(?:app/|pages/)?(?:main|app|framework|main-app)-([0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9.]+)*)\.js", html)
                    if v_match:
                        next_ver = v_match.group(1)

                ev = DetectionEvidence(
                    method=DetectionMethod.HTML,
                    source="html",
                    value="Next.js App Router / RSC state marker" if "__next_f" in html else "__NEXT_DATA__ state block",
                    confidence=100,
                    description="Detected Next.js React Server Component runtime / state marker"
                )
                if "Next.js" in detected_map:
                    detected_map["Next.js"]["confidence"] = 100
                    detected_map["Next.js"]["evidence"].append(ev)
                    if next_ver and not detected_map["Next.js"]["version"]:
                        detected_map["Next.js"]["version"] = next_ver
                else:
                    detected_map["Next.js"] = {
                        "confidence": 100,
                        "version": next_ver,
                        "category": TechnologyCategory.FRAMEWORK,
                        "cpes": [f"cpe:2.3:a:vercel:next.js:{next_ver or '*'}:*:*:*:*:*:*:*"],
                        "evidence": [ev],
                        "inferred": False
                    }

            # 6b. Nuxt 3 & Nuxt 2 (__NUXT_DATA__ / __NUXT__)
            if ("__NUXT_DATA__" in html or 'id="__nuxt"' in html or "window.__NUXT__" in html or "/_nuxt/" in html):
                nuxt_ver = None
                n_match = re.search(r"/_nuxt/(?:entry|manifest)\.([0-9]+\.[0-9]+\.[0-9]+)\.js", html)
                if n_match:
                    nuxt_ver = n_match.group(1)

                ev = DetectionEvidence(
                    method=DetectionMethod.HTML,
                    source="html",
                    value="Nuxt 3 SSR state marker (__NUXT_DATA__)" if "__NUXT_DATA__" in html else "<div id='__nuxt'>",
                    confidence=100,
                    description="Detected Nuxt.js SSR state container"
                )
                if "Nuxt.js" in detected_map:
                    detected_map["Nuxt.js"]["confidence"] = 100
                    detected_map["Nuxt.js"]["evidence"].append(ev)
                    if nuxt_ver and not detected_map["Nuxt.js"]["version"]:
                        detected_map["Nuxt.js"]["version"] = nuxt_ver
                else:
                    detected_map["Nuxt.js"] = {
                        "confidence": 100,
                        "version": nuxt_ver,
                        "category": TechnologyCategory.FRAMEWORK,
                        "cpes": [f"cpe:2.3:a:nuxt:nuxt.js:{nuxt_ver or '*'}:*:*:*:*:*:*:*"],
                        "evidence": [ev],
                        "inferred": False
                    }

            # 6c. Angular (ng-version DOM attribute)
            ng_match = re.search(r"""ng-version=["']([0-9]+(?:\.[0-9]+)+(?:-[a-zA-Z0-9.]+)*)["']""", html)
            if ng_match:
                ang_ver = ng_match.group(1)
                ev = DetectionEvidence(
                    method=DetectionMethod.HTML,
                    source="html",
                    value=f'ng-version="{ang_ver}"',
                    confidence=100,
                    description="Detected Angular root container with explicit ng-version"
                )
                detected_map["Angular"] = {
                    "confidence": 100,
                    "version": ang_ver,
                    "category": TechnologyCategory.FRAMEWORK,
                    "cpes": [f"cpe:2.3:a:angular:angular:{ang_ver}:*:*:*:*:*:*:*"],
                    "evidence": [ev],
                    "inferred": False
                }

            # 6d. Svelte & SvelteKit
            if ("__sveltekit" in html or "data-sveltekit-preload-data" in html or "svelte-" in html):
                ev = DetectionEvidence(
                    method=DetectionMethod.HTML,
                    source="html",
                    value="SvelteKit runtime container",
                    confidence=95,
                    description="Detected SvelteKit client hydrate / routing attributes"
                )
                detected_map["Svelte"] = {
                    "confidence": 95,
                    "version": None,
                    "category": TechnologyCategory.FRAMEWORK,
                    "cpes": ["cpe:2.3:a:svelte:svelte:*:*:*:*:*:*:*:*"],
                    "evidence": [ev],
                    "inferred": False
                }

            # 6e. Astro
            if ("data-astro-cid" in html or "<astro-island" in html):
                ev = DetectionEvidence(
                    method=DetectionMethod.HTML,
                    source="html",
                    value="Astro island component container",
                    confidence=100,
                    description="Detected Astro island hydration container"
                )
                detected_map["Astro"] = {
                    "confidence": 100,
                    "version": None,
                    "category": TechnologyCategory.FRAMEWORK,
                    "cpes": ["cpe:2.3:a:astro:astro:*:*:*:*:*:*:*:*"],
                    "evidence": [ev],
                    "inferred": False
                }

            # 6f. React (SSR Root)
            if "data-reactroot" in html or "data-reactid" in html:
                ev = DetectionEvidence(
                    method=DetectionMethod.HTML,
                    source="html",
                    value="data-reactroot",
                    confidence=95,
                    description="Detected React SSR root container"
                )
                if "React" not in detected_map:
                    detected_map["React"] = {
                        "confidence": 95,
                        "version": None,
                        "category": TechnologyCategory.LIBRARY,
                        "cpes": ["cpe:2.3:a:facebook:react:*:*:*:*:*:*:*:*"],
                        "evidence": [ev],
                        "inferred": False
                    }

            # 6g. Vue.js (data-v-app / data-v- scoped attributes)
            if "data-v-app" in html or "data-v-" in html:
                ev = DetectionEvidence(
                    method=DetectionMethod.HTML,
                    source="html",
                    value="data-v-app",
                    confidence=95,
                    description="Detected Vue 3 root application container"
                )
                if "Vue.js" not in detected_map:
                    detected_map["Vue.js"] = {
                        "confidence": 95,
                        "version": None,
                        "category": TechnologyCategory.FRAMEWORK,
                        "cpes": ["cpe:2.3:a:vuejs:vue.js:*:*:*:*:*:*:*:*"],
                        "evidence": [ev],
                        "inferred": False
                    }

            # 6h. Spring Boot (Whitelabel Error Page & Status)
            if "Whitelabel Error Page" in html or "This application has no explicit mapping for /error" in html:
                ev = DetectionEvidence(
                    method=DetectionMethod.HTML,
                    source="html",
                    value="Spring Boot Whitelabel Error Page",
                    confidence=100,
                    description="Detected Spring Boot default Whitelabel Error Page"
                )
                detected_map["Spring Boot"] = {
                    "confidence": 100,
                    "version": None,
                    "category": TechnologyCategory.FRAMEWORK,
                    "cpes": ["cpe:2.3:a:pivotal_software:spring_boot:*:*:*:*:*:*:*:*"],
                    "evidence": [ev],
                    "inferred": False
                }

            # 6i. Laravel (Whoops / Ignition Debug Page)
            if "Whoops! There was an error." in html or "window.Ignition" in html:
                ev = DetectionEvidence(
                    method=DetectionMethod.HTML,
                    source="html",
                    value="Laravel Whoops / Ignition debug screen",
                    confidence=100,
                    description="Detected Laravel Ignition / Whoops unhardened error trace"
                )
                detected_map["Laravel"] = {
                    "confidence": 100,
                    "version": None,
                    "category": TechnologyCategory.FRAMEWORK,
                    "cpes": ["cpe:2.3:a:laravel:laravel:*:*:*:*:*:*:*:*"],
                    "evidence": [ev],
                    "inferred": False
                }

            # 6j. ASP.NET (Yellow Screen of Death / YSOD)
            if "Server Error in '/' Application." in html or "ASP.NET Version:" in html:
                asp_ver = None
                asp_m = re.search(r"ASP\.NET Version:([0-9.]+)", html)
                if asp_m:
                    asp_ver = asp_m.group(1)
                ev = DetectionEvidence(
                    method=DetectionMethod.HTML,
                    source="html",
                    value="ASP.NET Yellow Screen of Death (YSOD)",
                    confidence=100,
                    description="Detected ASP.NET YSOD unhardened error trace"
                )
                detected_map["ASP.NET"] = {
                    "confidence": 100,
                    "version": asp_ver,
                    "category": TechnologyCategory.FRAMEWORK,
                    "cpes": [f"cpe:2.3:a:microsoft:asp.net:{asp_ver or '*'}:*:*:*:*:*:*:*"],
                    "evidence": [ev],
                    "inferred": False
                }

        # 7. Implication & Exclusion Graph Resolution
        resolved_map = ImplicationResolver.resolve(detected_map, self.signatures_by_name)

        # 8. Transform to Core Domain TechnologyFingerprint Model
        alias_map = {
            "tailwind": "Tailwind CSS",
            "tailwindcss": "Tailwind CSS",
            "next": "Next.js",
            "nextjs": "Next.js",
            "nuxt": "Nuxt.js",
            "nuxtjs": "Nuxt.js",
            "vue": "Vue.js",
            "vuejs": "Vue.js",
            "reactjs": "React",
            "angularjs": "Angular",
            "apache": "Apache HTTP Server",
            "spring": "Spring Boot",
            "spring boot": "Spring Boot",
        }

        final_list: List[TechnologyFingerprint] = []
        for name, data in resolved_map.items():
            canon_name = alias_map.get(name.lower(), name)
            conf = data.get("confidence", 80)
            ver = data.get("version")
            parent_name = data.get("inferred_from")
            raw_cpes = data.get("cpes", [])
            
            cpe_cands = []
            for c in raw_cpes:
                cpe_str = c.replace("{version}", ver if ver else "*")
                if ver and ":*:" in cpe_str:
                    parts = cpe_str.split(":")
                    if len(parts) >= 6 and parts[5] in ("*", ""):
                        parts[5] = ver
                        cpe_str = ":".join(parts)
                cpe_cands.append(CPECandidate(cpe=cpe_str, confidence=conf))

            ev_list = data.get("evidence", [])

            cat = data.get("category", TechnologyCategory.FRAMEWORK)
            if isinstance(cat, str):
                for tc in TechnologyCategory:
                    if tc.name.lower() == cat.lower() or tc.value.lower() == cat.lower():
                        cat = tc
                        break
                if isinstance(cat, str):
                    cat = TechnologyCategory.FRAMEWORK

            sig_rule = self.signatures_by_name.get(name) or self.signatures_by_name.get(canon_name)
            domain_val = data.get("domain") or (sig_rule.domain if sig_rule else "web")
            vendor_val = data.get("vendor") or (sig_rule.vendor if sig_rule else None)

            is_inferred = data.get("inferred", False)
            vuln_status = "EXACT" if (ver and cpe_cands) else ("PARTIAL" if cpe_cands else "UNTESTED")

            fp = TechnologyFingerprint(
                name=canon_name,
                version=ver,
                category=cat,
                confidence=conf,
                confidence_band=get_confidence_band(conf),
                evidence=ev_list,
                evidence_count=len(ev_list),
                version_status=DetectionStatus.VERIFIED if ver else DetectionStatus.UNKNOWN,
                parent=alias_map.get(parent_name.lower(), parent_name) if parent_name else None,
                cpe_candidates=cpe_cands,
                inferred=is_inferred,
                direct_detection=not is_inferred,
                domain=domain_val,
                vendor=vendor_val,
                vulnerability_status=vuln_status
            )
            final_list.append(fp)

        return final_list
