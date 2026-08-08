import re
from typing import List, Optional
from pulse.domain.models import DetectionEvidence, DetectionMethod, TechnologyCategory, CPECandidate, EvidenceReliability
from pulse.website.signatures.base import TechnologySignature

class NextJsSignature(TechnologySignature):
    @property
    def signature_id(self) -> str:
        return "nextjs"

    @property
    def name(self) -> str:
        return "Next.js"

    @property
    def category(self) -> TechnologyCategory:
        return TechnologyCategory.FRAMEWORK

    @property
    def priority(self) -> int:
        return 100

    @property
    def provides_version(self) -> bool:
        return True

    @property
    def provides_cpe_candidates(self) -> bool:
        return True

    @property
    def ecosystem(self) -> Optional[str]:
        return "npm"

    @property
    def correlation_supported(self) -> bool:
        return True

    def match(self, headers: dict, html: str, cookies: dict, scripts: List[str]) -> List[DetectionEvidence]:
        evidence = []

        # 1. Header Checks
        x_powered_by = headers.get("X-Powered-By", "")
        if "next.js" in x_powered_by.lower():
            evidence.append(DetectionEvidence(
                method=DetectionMethod.HEADER,
                source="X-Powered-By",
                value=x_powered_by,
                confidence=95,
                description="Next.js detected via X-Powered-By header",
                reliability=EvidenceReliability.HIGH
            ))

        if "x-nextjs-cache" in headers or "x-nextjs-matched-path" in headers:
            evidence.append(DetectionEvidence(
                method=DetectionMethod.HEADER,
                source="Cache/Routing Headers",
                value=f"Matched: {[h for h in ['x-nextjs-cache', 'x-nextjs-matched-path'] if h in headers]}",
                confidence=95,
                description="Next.js specific cache/routing headers present",
                reliability=EvidenceReliability.VERIFIED
            ))

        # 2. HTML Checks
        if "__NEXT_DATA__" in html:
            evidence.append(DetectionEvidence(
                method=DetectionMethod.HTML,
                source="HTML Body",
                value="__NEXT_DATA__",
                confidence=95,
                description="Next.js page state global __NEXT_DATA__ block found",
                reliability=EvidenceReliability.VERIFIED
            ))

        if "_next/static" in html:
            evidence.append(DetectionEvidence(
                method=DetectionMethod.HTML,
                source="HTML Body",
                value="_next/static",
                confidence=90,
                description="Next.js static asset path reference in HTML",
                reliability=EvidenceReliability.HIGH
            ))

        # 3. Scripts Checks
        for script in scripts:
            if "_next/static" in script:
                evidence.append(DetectionEvidence(
                    method=DetectionMethod.SCRIPT,
                    source="Script Src",
                    value=script,
                    confidence=90,
                    description="Script loading from Next.js static directory",
                    reliability=EvidenceReliability.HIGH
                ))

        return evidence

    def extract_version(self, headers: dict, html: str, cookies: dict, scripts: List[str]) -> Optional[str]:
        # Try to extract version from headers
        x_powered_by = headers.get("X-Powered-By", "")
        match = re.search(r'next\.js/?([\d\.]+)', x_powered_by, re.IGNORECASE)
        if match:
            return match.group(1)

        # Try to extract version from scripts e.g. /_next/static/chunks/main-13.4.12.js or similar
        # Build manifest version check
        # Next.js main bundles often have a hash or version: _next/static/BUILD_ID/pages/index.js
        # Look for _next/static/([\d\.]+)/ or _next/static/chunks/.*-([\d\.]+)\.js
        for script in scripts:
            match = re.search(r'_next/static/chunks/[^/]+-([\d\.]+)\.js', script)
            if match:
                return match.group(1)
            # Maybe from a CDN import: next@12.3.4
            match = re.search(r'next.js@([\d\.]+)', script, re.IGNORECASE)
            if match:
                return match.group(1)

        return None

    def get_cpe_candidates(self, version: Optional[str]) -> List[CPECandidate]:
        ver = version if version else "*"
        return [
            CPECandidate(cpe=f"cpe:2.3:a:vercel:next.js:{ver}:*:*:*:*:*:*:*", confidence=95)
        ]
