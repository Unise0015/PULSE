"""
Declarative Technology Engine for PULSE Web Subsystem.
Orchestrates pre-filtered index searching, evidence collection, version extraction,
confidence calculation, and implication resolution.
"""

import re
import json
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
        if html_body and len(html_body) > MAX_BODY_SIZE:
            logger.warning("Truncating HTML body from %d bytes to MAX_BODY_SIZE (%d bytes) for safety.", len(html_body), MAX_BODY_SIZE)
            html_body = html_body[:MAX_BODY_SIZE]

        # Case-insensitive header dictionary normalization
        normalized_headers = {k.lower().strip(): v for k, v in headers.items()}
        normalized_cookies = {k.lower().strip(): v for k, v in cookies.items()}

        detected_map: Dict[str, Dict[str, Any]] = {}

        def record_detection(
            tech_name: str,
            rule_confidence: int,
            evidence: DeclarativeEvidence,
            version: Optional[str]
        ):
            # Canonical name mapping
            canon_name = tech_name
            if tech_name in ("Nuxt", "nuxtjs"):
                canon_name = "Nuxt.js"
            elif tech_name in ("Next", "nextjs"):
                canon_name = "Next.js"
            elif tech_name in ("Tailwind", "tailwind"):
                canon_name = "Tailwind CSS"
            elif tech_name in ("Vue", "vuejs"):
                canon_name = "Vue.js"
            elif tech_name in ("React", "reactjs"):
                canon_name = "React"
            elif tech_name in ("Angular", "angularjs"):
                canon_name = "Angular"

            tech_rule = self.loader.technology_rules.get(canon_name) or self.loader.technology_rules.get(tech_name)
            categories = tech_rule.categories if tech_rule else ["Web Technology"]
            cpes = tech_rule.cpes if tech_rule else []

            if canon_name not in detected_map:
                detected_map[canon_name] = {
                    "confidence": rule_confidence,
                    "version": version,
                    "category": categories[0] if categories else "Web Technology",
                    "cpes": cpes,
                    "evidence": [evidence] if evidence else [],
                    "inferred": False,
                    "inferred_from": None
                }
            else:
                existing = detected_map[canon_name]
                existing["confidence"] = min(100, existing["confidence"] + (rule_confidence // 2))
                if evidence:
                    existing["evidence"].append(evidence)
                if not existing["version"] and version:
                    existing["version"] = version
                if not existing["cpes"] and cpes:
                    existing["cpes"] = cpes

        # 1. Match Headers (including compound tokens)
        for h_key, h_val in normalized_headers.items():
            if h_key in self.index.headers:
                for tech_name, rule in self.index.headers[h_key]:
                    result = PatternMatcher.match_rule(rule, h_val, source="header", header_name=h_key)
                    if result:
                        ev, ver = result
                        record_detection(tech_name, rule.confidence, ev, ver)

            # Special header handling: Server & X-Powered-By tokenization
            if h_key in ("server", "x-powered-by"):
                # Matches Apache/2.4.58, PHP/8.2.14, OpenSSL/3.0.13, nginx/1.24.0, Next.js
                tokens = re.findall(r'([a-zA-Z0-9_.-]+)(?:/([0-9.]+))?', h_val)
                for t_name, t_ver in tokens:
                    low_t = t_name.lower()
                    if low_t in ("apache", "httpd"):
                        record_detection("Apache HTTP Server", 100, DeclarativeEvidence(source="header", matched_value=f"{t_name}/{t_ver}" if t_ver else t_name, pattern=h_val, confidence=100, header_name=h_key, version=t_ver or None), t_ver or None)
                    elif low_t == "nginx":
                        record_detection("Nginx", 100, DeclarativeEvidence(source="header", matched_value=f"{t_name}/{t_ver}" if t_ver else t_name, pattern=h_val, confidence=100, header_name=h_key, version=t_ver or None), t_ver or None)
                    elif low_t == "php":
                        record_detection("PHP", 100, DeclarativeEvidence(source="header", matched_value=f"{t_name}/{t_ver}" if t_ver else t_name, pattern=h_val, confidence=100, header_name=h_key, version=t_ver or None), t_ver or None)
                    elif low_t == "openssl":
                        record_detection("OpenSSL", 100, DeclarativeEvidence(source="header", matched_value=f"{t_name}/{t_ver}" if t_ver else t_name, pattern=h_val, confidence=100, header_name=h_key, version=t_ver or None), t_ver or None)
                    elif "next" in low_t:
                        record_detection("Next.js", 100, DeclarativeEvidence(source="header", matched_value=t_name, pattern=h_val, confidence=100, header_name=h_key, version=t_ver or None), t_ver or None)

        # 2. Match Cookies
        for c_key, c_val in normalized_cookies.items():
            if c_key in self.index.cookies:
                for tech_name, rule in self.index.cookies[c_key]:
                    result = PatternMatcher.match_rule(rule, c_val, source="cookie", cookie_name=c_key)
                    if result:
                        ev, ver = result
                        record_detection(tech_name, rule.confidence, ev, ver)

        # 3. Match Meta Tags (Attribute-order agnostic)
        if html_body and ("<meta" in html_body.lower()):
            for meta_tag in re.finditer(r'<meta[^>]+>', html_body, re.IGNORECASE):
                tag_str = meta_tag.group(0)
                name_m = re.search(r'(?:name|property|http-equiv)=["\']([^"\']+)["\']', tag_str, re.IGNORECASE)
                content_m = re.search(r'content=["\']([^"\']+)["\']', tag_str, re.IGNORECASE)
                if name_m and content_m:
                    m_name = name_m.group(1).strip()
                    m_val = content_m.group(1).strip()
                    m_key = m_name.lower()
                    if m_key in self.index.meta:
                        for tech_name, rule in self.index.meta[m_key]:
                            result = PatternMatcher.match_rule(rule, m_val, source="meta", meta_name=m_name)
                            if result:
                                ev, ver = result
                                record_detection(tech_name, rule.confidence, ev, ver)

        # 4. Match Script and Asset URLs (Per-URL evaluation)
        all_asset_urls = list(script_urls or [])
        if html_body:
            # Extract script src
            s_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html_body, re.IGNORECASE)
            all_asset_urls.extend(s_srcs)
            # Extract link href (stylesheets, modulepreload, preload)
            l_hrefs = re.findall(r'<link[^>]+href=["\']([^"\']+)["\']', html_body, re.IGNORECASE)
            all_asset_urls.extend(l_hrefs)

        # Deduplicate asset URLs
        unique_asset_urls = list(dict.fromkeys(all_asset_urls))

        for url_str in unique_asset_urls:
            for tech_name, rule in self.index.script_src_rules:
                result = PatternMatcher.match_rule(rule, url_str, source="script")
                if result:
                    ev, ver = result
                    record_detection(tech_name, rule.confidence, ev, ver)

            # Direct CDN / Package URL version parsing:
            u_low = url_str.lower()
            if "tailwindcss" in u_low or "tailwind" in u_low:
                ver = PatternMatcher.normalize_version(url_str)
                record_detection("Tailwind CSS", 100, DeclarativeEvidence(source="script", matched_value=url_str, pattern="tailwindcss", confidence=100, version=ver), ver)
            elif "bootstrap" in u_low:
                ver = PatternMatcher.normalize_version(url_str)
                record_detection("Bootstrap", 100, DeclarativeEvidence(source="script", matched_value=url_str, pattern="bootstrap", confidence=100, version=ver), ver)
            elif "jquery" in u_low and "jquery-migrate" not in u_low and "jquery." in u_low:
                ver = PatternMatcher.normalize_version(url_str)
                record_detection("jQuery", 100, DeclarativeEvidence(source="script", matched_value=url_str, pattern="jquery", confidence=100, version=ver), ver)
            elif "jquery-migrate" in u_low:
                ver = PatternMatcher.normalize_version(url_str)
                record_detection("jQuery Migrate", 100, DeclarativeEvidence(source="script", matched_value=url_str, pattern="jquery-migrate", confidence=100, version=ver), ver)

        # 5. DOM Framework Markers & HTML Body Matching
        if html_body:
            # 5a. Angular DOM detection: ng-version="17.0.8"
            ng_match = re.search(r'ng-version=["\']([0-9.]+)["\']', html_body)
            if ng_match:
                ng_ver = ng_match.group(1)
                record_detection("Angular", 100, DeclarativeEvidence(source="html", matched_value=f'ng-version="{ng_ver}"', pattern="ng-version", confidence=100, version=ng_ver), ng_ver)

            # 5b. Next.js DOM markers: __NEXT_DATA__, id="__next", styled-jsx
            if "__NEXT_DATA__" in html_body:
                next_ver = None
                try:
                    data_match = re.search(r'<script[^>]+id=["\']__NEXT_DATA__["\'][^>]*>(.*?)</script>', html_body, re.DOTALL)
                    if data_match:
                        json_str = data_match.group(1).strip()
                        data = json.loads(json_str)
                        build_id = str(data.get("buildId", ""))
                        b_ver = PatternMatcher.normalize_version(build_id)
                        if b_ver:
                            next_ver = b_ver
                except Exception:
                    pass
                if not next_ver:
                    chunk_m = re.search(r'/_next/static/chunks/[^"\']*-([0-9.]+)\.js', html_body)
                    if chunk_m:
                        next_ver = chunk_m.group(1)
                record_detection("Next.js", 100, DeclarativeEvidence(source="html", matched_value="__NEXT_DATA__", pattern="__NEXT_DATA__", confidence=100, version=next_ver), next_ver)

            # 5c. Vue.js & Nuxt DOM markers: id="__nuxt", data-v-, data-server-rendered
            if 'id="__nuxt"' in html_body or 'data-v-app' in html_body or 'data-v-' in html_body:
                record_detection("Vue.js", 95, DeclarativeEvidence(source="html", matched_value="data-v-app", pattern="data-v-", confidence=95), None)
            if 'id="__nuxt"' in html_body or '_nuxt/' in html_body:
                nuxt_ver = None
                n_match = re.search(r'/_nuxt/[^"\']*?([0-9]+\.[0-9]+\.[0-9]+)', html_body)
                if n_match:
                    nuxt_ver = n_match.group(1)
                record_detection("Nuxt.js", 100, DeclarativeEvidence(source="html", matched_value="id=__nuxt", pattern="__nuxt", confidence=100, version=nuxt_ver), nuxt_ver)

            # 5d. React SSR markers: data-reactroot
            if 'data-reactroot' in html_body or 'data-reactid' in html_body:
                record_detection("React", 95, DeclarativeEvidence(source="html", matched_value="data-reactroot", pattern="data-reactroot", confidence=95), None)

            # 5e. General HTML rules
            for tech_name, rule in self.index.html_rules:
                result = PatternMatcher.match_rule(rule, html_body, source="html")
                if result:
                    ev, ver = result
                    record_detection(tech_name, rule.confidence, ev, ver)

        # ── NEW DETECTION PHASES ─────────────────────────────────────────

        # 6. JavaScript Inline Version Comment Detection
        # Catches: /*! jQuery v3.6.0 */, /** @license React v18.2.0 */, /* Bootstrap v5.3.0 */
        if html_body:
            _JS_VERSION_COMMENTS = [
                # (regex_pattern, technology_name, confidence)
                (r'/\*[!*]?\s*jQuery\s+v?([0-9]+\.[0-9]+\.[0-9]+)', "jQuery", 100),
                (r'/\*[!*]?\s*jQuery\s+Migrate\s+v?([0-9]+\.[0-9]+\.[0-9]+)', "jQuery Migrate", 100),
                (r'/\*[!*]?\s*Bootstrap\s+v?([0-9]+\.[0-9]+\.[0-9]+)', "Bootstrap", 100),
                (r'@license\s+React\s+v?([0-9]+\.[0-9]+\.[0-9]+)', "React", 100),
                (r'/\*[!*]?\s*Lodash\s+v?([0-9]+\.[0-9]+\.[0-9]+)', "Lodash", 100),
                (r'/\*[!*]?\s*Underscore\.js\s+v?([0-9]+\.[0-9]+\.[0-9]+)', "Underscore.js", 100),
                (r'/\*[!*]?\s*Handlebars\s+v?([0-9]+\.[0-9]+\.[0-9]+)', "Handlebars", 100),
                (r'/\*[!*]?\s*Backbone\.js\s+v?([0-9]+\.[0-9]+\.[0-9]+)', "Backbone.js", 100),
                (r'/\*[!*]?\s*Moment\.js\s+v?([0-9]+\.[0-9]+\.[0-9]+)', "Moment.js", 100),
                (r'/\*[!*]?\s*D3\.js\s+v?([0-9]+\.[0-9]+\.[0-9]+)', "D3.js", 100),
                (r'/\*[!*]?\s*Chart\.js\s+v?([0-9]+\.[0-9]+\.[0-9]+)', "Chart.js", 100),
                (r'/\*[!*]?\s*Vue\.js\s+v?([0-9]+\.[0-9]+\.[0-9]+)', "Vue.js", 95),
                (r'/\*[!*]?\s*Axios\s+v?([0-9]+\.[0-9]+\.[0-9]+)', "Axios", 90),
                (r'/\*[!*]?\s*Swiper\s+v?([0-9]+\.[0-9]+\.[0-9]+)', "Swiper", 90),
                (r'/\*[!*]?\s*Popper\s+v?([0-9]+\.[0-9]+\.[0-9]+)', "Popper.js", 90),
                (r'/\*[!*]?\s*Select2\s+v?([0-9]+\.[0-9]+\.[0-9]+)', "Select2", 90),
                (r'/\*[!*]?\s*Slick\s+v?([0-9]+\.[0-9]+\.[0-9]+)', "Slick", 90),
                (r'/\*[!*]?\s*Owl\s+Carousel\s+v?([0-9]+\.[0-9]+\.[0-9]+)', "Owl Carousel", 90),
                (r'/\*[!*]?\s*Lightbox\s+v?([0-9]+\.[0-9]+\.[0-9]+)', "Lightbox", 90),
                (r'/\*[!*]?\s*Animate\.css\s+v?([0-9]+\.[0-9]+\.[0-9]+)', "Animate.css", 90),
                (r'/\*[!*]?\s*normalize\.css\s+v?([0-9]+\.[0-9]+\.[0-9]+)', "Normalize.css", 85),
                (r'/\*[!*]?\s*Modernizr\s+v?([0-9]+\.[0-9]+\.[0-9]+)', "Modernizr", 90),
                (r'/\*[!*]?\s*Socket\.IO\s+v?([0-9]+\.[0-9]+\.[0-9]+)', "Socket.IO", 90),
                (r'/\*[!*]?\s*gsap\s+v?([0-9]+\.[0-9]+\.[0-9]+)', "GSAP", 90),
                (r'/\*[!*]?\s*GreenSock\s+v?([0-9]+\.[0-9]+\.[0-9]+)', "GSAP", 90),
                (r'/\*[!*]?\s*Leaflet\s+v?([0-9]+\.[0-9]+\.[0-9]+)', "Leaflet", 90),
                (r'/\*[!*]?\s*AOS\s+v?([0-9]+\.[0-9]+\.[0-9]+)', "AOS", 85),
                (r'/\*[!*]?\s*highlight\.js\s+v?([0-9]+\.[0-9]+\.[0-9]+)', "Highlight.js", 85),
                (r'/\*[!*]?\s*Prism\.js\s+v?([0-9]+\.[0-9]+\.[0-9]+)', "Prism", 85),
                (r'/\*[!*]?\s*Ember\.js\s+v?([0-9]+\.[0-9]+\.[0-9]+)', "Ember.js", 95),
            ]
            for pattern, tech_name, conf in _JS_VERSION_COMMENTS:
                m = re.search(pattern, html_body, re.IGNORECASE)
                if m:
                    ver = m.group(1)
                    record_detection(tech_name, conf, DeclarativeEvidence(
                        source="html", matched_value=m.group(0)[:120],
                        pattern="js_version_comment", confidence=conf, version=ver
                    ), ver)

        # 7. JavaScript Global Variable & Object Pattern Detection
        # Catches framework fingerprints embedded in inline scripts
        if html_body:
            _JS_GLOBAL_PATTERNS = [
                (r'jQuery\.fn\.jquery\s*=\s*["\']([0-9.]+)["\']', "jQuery", 100),
                (r'jQuery\s+v([0-9]+\.[0-9]+\.[0-9]+)', "jQuery", 100),
                (r'jquery.*?([0-9]+\.[0-9]+\.[0-9]+).*?\.min\.js', "jQuery", 85),
                (r'Backbone\.VERSION\s*=\s*["\']([0-9.]+)["\']', "Backbone.js", 95),
                (r'_\.VERSION\s*=\s*["\']([0-9.]+)["\']', "Lodash", 80),
                (r'Modernizr\s+([0-9]+\.[0-9]+\.[0-9]+)', "Modernizr", 90),
                (r'window\.__GATSBY', "Gatsby", 95),
                (r'__gatsby', "Gatsby", 85),
                (r'window\.__remixContext', "Remix", 95),
                (r'__remixContext', "Remix", 85),
                (r'__SVELTE_HMR', "Svelte", 90),
                (r'Ember\.VERSION\s*=\s*["\']([0-9.]+)["\']', "Ember.js", 95),
                (r'window\.Shopify', "Shopify", 95),
                (r'Shopify\.shop\s*=', "Shopify", 95),
                (r'window\.Webflow', "Webflow", 95),
                (r'window\.wixBiSession', "Wix", 95),
                (r'window\.__wix', "Wix", 90),
                (r'window\.squarespaceContext', "Squarespace", 95),
                (r'Static\.SQUARESPACE_CONTEXT', "Squarespace", 95),
                (r'window\.google_tag_manager', "Google Tag Manager", 90),
                (r'googletagmanager\.com/gtm\.js', "Google Tag Manager", 95),
                (r'google-analytics\.com/analytics\.js', "Google Analytics", 95),
                (r'gtag\([\'\"]config[\'\"]\s*,\s*[\'\"]G-', "Google Analytics", 90),
                (r'gtag\([\'\"]config[\'\"]\s*,\s*[\'\"]UA-', "Google Analytics", 90),
                (r'connect\.facebook\.net/.*/sdk\.js', "Facebook SDK", 85),
                (r'platform\.twitter\.com/widgets\.js', "Twitter Widgets", 85),
                (r'cdn\.jsdelivr\.net/npm/alpinejs', "Alpine.js", 95),
                (r'x-data\s*=\s*["\']', "Alpine.js", 80),
                (r'window\.htmx', "htmx", 95),
                (r'hx-get\s*=|hx-post\s*=|hx-trigger\s*=', "htmx", 90),
                (r'livewire', "Laravel Livewire", 80),
                (r'window\.livewire', "Laravel Livewire", 95),
                (r'Turbo\.connectStreamSource|data-turbo-frame', "Hotwire Turbo", 90),
                (r'<turbo-frame', "Hotwire Turbo", 95),
                (r'stimulus', "Stimulus", 70),
                (r'data-controller\s*=', "Stimulus", 90),
            ]
            for pattern, tech_name, conf in _JS_GLOBAL_PATTERNS:
                m = re.search(pattern, html_body, re.IGNORECASE)
                if m:
                    ver = m.group(1) if m.lastindex and m.lastindex >= 1 else None
                    record_detection(tech_name, conf, DeclarativeEvidence(
                        source="html", matched_value=m.group(0)[:120],
                        pattern="js_global_pattern", confidence=conf, version=ver
                    ), ver)

        # 8. CSS Framework Class & Data-Attribute Detection
        # Catches UI component frameworks by their characteristic class prefixes
        if html_body:
            _CSS_CLASS_PATTERNS = [
                # (substring_to_check, regex_for_precision, technology_name, confidence)
                ('class="MuiButton', r'class="[^"]*\bMui[A-Z]', "Material UI (MUI)", 95),
                ("class='MuiButton", r"class='[^']*\bMui[A-Z]", "Material UI (MUI)", 95),
                ('class="chakra-', r'class="[^"]*\bchakra-', "Chakra UI", 95),
                ('class="ant-', r'class="[^"]*\bant-', "Ant Design", 95),
                ('class="el-', r'class="[^"]*\bel-[a-z]', "Element UI", 90),
                ('class="v-btn', r'class="[^"]*\bv-(?:btn|card|app|toolbar|list)', "Vuetify", 90),
                ('data-bs-', r'data-bs-(?:toggle|target|dismiss|ride)', "Bootstrap", 90),
                ('class="btn btn-', r'class="[^"]*\bbtn\s+btn-(?:primary|secondary|success|danger|warning|info)', "Bootstrap", 75),
                ('class="fa ', r'class="[^"]*\bfa[srbl]?\s+fa-', "Font Awesome", 90),
                ('class="fas ', r'class="[^"]*\bfas\s+fa-', "Font Awesome", 90),
                ('class="bi ', r'class="[^"]*\bbi\s+bi-', "Bootstrap Icons", 85),
                ('class="material-icons', r'class="[^"]*\bmaterial-icons', "Google Material Icons", 85),
                ('class="mdi ', r'class="[^"]*\bmdi\s+mdi-', "Material Design Icons", 85),
                ('class="ion-', r'class="[^"]*\bion-', "Ionicons", 80),
                ('class="ti-', r'class="[^"]*\bti-[a-z]', "Themify Icons", 75),
                ('class="glyphicon', r'class="[^"]*\bglyphicon\s+glyphicon-', "Bootstrap (Glyphicons)", 85),
                ('class="uk-', r'class="[^"]*\buk-(?:grid|container|section|navbar|card)', "UIkit", 90),
                ('class="pure-', r'class="[^"]*\bpure-(?:g|u|menu|table|form|button)', "Pure.css", 85),
                ('class="foundation', r'class="[^"]*\b(?:row|columns|small-|medium-|large-)\d', "Foundation", 75),
                ('class="w3-', r'class="[^"]*\bw3-(?:container|row|col|bar|btn|card)', "W3.CSS", 85),
                ('class="bulma', r'class="[^"]*\b(?:is-primary|is-info|is-success|column|hero)\b', "Bulma", 70),
                ('class="tailwind', None, "Tailwind CSS", 60),
                ('class="prose ', r'class="[^"]*\bprose\b', "Tailwind CSS", 60),
                ('class="sr-only', None, "Bootstrap", 60),
            ]
            html_lower = html_body[:500000]  # Limit scan to first 500KB for performance
            for substring, regex, tech_name, conf in _CSS_CLASS_PATTERNS:
                if substring in html_lower:
                    if regex:
                        m = re.search(regex, html_lower)
                        if m:
                            record_detection(tech_name, conf, DeclarativeEvidence(
                                source="html", matched_value=m.group(0)[:100],
                                pattern="css_class_pattern", confidence=conf
                            ), None)
                    else:
                        record_detection(tech_name, conf, DeclarativeEvidence(
                            source="html", matched_value=substring,
                            pattern="css_class_pattern", confidence=conf
                        ), None)

        # 9. URL Path Structure Fingerprinting
        # Detect technologies from characteristic asset paths embedded in the page
        if html_body:
            _URL_PATH_PATTERNS = [
                # (regex_pattern, technology_name, confidence, version_group_or_none)
                (r'/wp-content/(?:themes|plugins|uploads)/', "WordPress", 100, None),
                (r'/wp-includes/(?:js|css|images)/', "WordPress", 100, None),
                (r'/wp-json/', "WordPress", 95, None),
                (r'/xmlrpc\.php', "WordPress", 90, None),
                (r'/sites/default/files/', "Drupal", 95, None),
                (r'/core/misc/drupal\.js', "Drupal", 100, None),
                (r'/misc/drupal\.js', "Drupal", 95, None),
                (r'/modules/(?:system|node|user|field)/', "Drupal", 85, None),
                (r'/media/(?:system|jui|com_)/', "Joomla", 90, None),
                (r'/administrator/', "Joomla", 70, None),
                (r'/templates/(?:system|beez|protostar)/', "Joomla", 90, None),
                (r'/_next/static/', "Next.js", 100, None),
                (r'/_next/data/', "Next.js", 100, None),
                (r'/_nuxt/', "Nuxt.js", 100, None),
                (r'/__remix/', "Remix", 100, None),
                (r'/assets/(?:[a-z0-9]+-)?[a-f0-9]{8}\.(?:js|css)', "Vite", 70, None),
                (r'/build/assets/[^"\']+\.(?:js|css)', "Laravel Mix/Vite", 65, None),
                (r'/static/(?:js|css)/main\.[a-f0-9]+\.(?:js|css)', "Create React App", 85, None),
                (r'/bundles/[a-z]+bundle/', "Symfony", 85, None),
                (r'/static/CACHE/(?:js|css)/', "Django", 80, None),
                (r'/assets/application-[a-f0-9]+\.(?:js|css)', "Ruby on Rails", 80, None),
                (r'/packs/js/', "Ruby on Rails (Webpacker)", 85, None),
                (r'cdn\.shopify\.com/s/files/', "Shopify", 100, None),
                (r'squarespace\.com/', "Squarespace", 90, None),
                (r'static\.wixstatic\.com/', "Wix", 100, None),
                (r'parastorage\.com/', "Wix", 95, None),
                (r'webflow\.com/', "Webflow", 90, None),
                (r'/ghost/api/', "Ghost", 95, None),
                (r'ghost\.io/', "Ghost", 90, None),
                (r'/typo3/', "TYPO3", 95, None),
                (r'/fileadmin/', "TYPO3", 75, None),
                (r'/umbraco/', "Umbraco", 95, None),
                (r'/sitecore/', "Sitecore", 95, None),
                (r'/kentico/', "Kentico", 95, None),
                (r'cdn\.ampproject\.org/', "AMP", 95, None),
                (r'/ember-cli/', "Ember.js", 90, None),
            ]
            for pattern, tech_name, conf, ver_grp in _URL_PATH_PATTERNS:
                m = re.search(pattern, html_body, re.IGNORECASE)
                if m:
                    ver = m.group(ver_grp) if ver_grp and m.lastindex and m.lastindex >= ver_grp else None
                    record_detection(tech_name, conf, DeclarativeEvidence(
                        source="html", matched_value=m.group(0)[:120],
                        pattern="url_path_fingerprint", confidence=conf, version=ver
                    ), ver)

        # ── END NEW DETECTION PHASES ─────────────────────────────────────

        # 10. Implication Graph & Exclusion Resolution
        resolved_map = ImplicationResolver.resolve(detected_map, self.loader.technology_rules)

        # 7. Construct TechnologyFingerprint objects
        fingerprints: List[TechnologyFingerprint] = []

        for name, data in resolved_map.items():
            cpe_cands = []
            version_str = data.get("version")
            cpe_list = data.get("cpes", [])

            for cpe_base in cpe_list:
                if cpe_base:
                    final_cpe = cpe_base
                    if version_str and ":*:" in cpe_base:
                        parts = cpe_base.split(":")
                        if len(parts) >= 5:
                            final_cpe = f"cpe:2.3:a:{parts[3]}:{parts[4]}:{version_str}:*:*:*:*:*:*:*"
                    cpe_cands.append(CPECandidate(cpe=final_cpe, confidence=data["confidence"]))

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
                vulnerability_status=vuln_stat,
                correlation_supported=True
            )
            fingerprints.append(fp)

        # Sort by confidence descending
        fingerprints.sort(key=lambda x: (not x.inferred, x.confidence, bool(x.version)), reverse=True)
        return fingerprints
