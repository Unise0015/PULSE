from typing import List, Optional
from pulse.domain.models import DetectionEvidence, DetectionMethod, TechnologyCategory, CPECandidate, EvidenceReliability
from pulse.website.signatures.base import TechnologySignature

class CloudflareSignature(TechnologySignature):
    @property
    def signature_id(self) -> str:
        return "cloudflare"

    @property
    def name(self) -> str:
        return "cloudflare"

    @property
    def category(self) -> TechnologyCategory:
        return TechnologyCategory.CDN

    def match(self, headers: dict, html: str, cookies: dict, scripts: List[str]) -> List[DetectionEvidence]:
        evidence = []
        server = headers.get("Server", "").lower()
        if "cloudflare" in server:
            evidence.append(DetectionEvidence(
                method=DetectionMethod.HEADER,
                source="Server",
                value="cloudflare",
                confidence=95,
                description="Cloudflare Server header present",
                reliability=EvidenceReliability.HIGH
            ))
        if "cf-ray" in headers:
            evidence.append(DetectionEvidence(
                method=DetectionMethod.HEADER,
                source="cf-ray",
                value=headers["cf-ray"],
                confidence=95,
                description="Cloudflare cf-ray header present",
                reliability=EvidenceReliability.VERIFIED
            ))
        return evidence


class FastlySignature(TechnologySignature):
    @property
    def signature_id(self) -> str:
        return "fastly"

    @property
    def name(self) -> str:
        return "fastly"

    @property
    def category(self) -> TechnologyCategory:
        return TechnologyCategory.CDN

    def match(self, headers: dict, html: str, cookies: dict, scripts: List[str]) -> List[DetectionEvidence]:
        evidence = []
        server = headers.get("Server", "").lower()
        if "fastly" in server:
            evidence.append(DetectionEvidence(
                method=DetectionMethod.HEADER,
                source="Server",
                value="fastly",
                confidence=95,
                description="Fastly Server header present",
                reliability=EvidenceReliability.HIGH
            ))
        if "x-fastly-request-id" in headers:
            evidence.append(DetectionEvidence(
                method=DetectionMethod.HEADER,
                source="x-fastly-request-id",
                value=headers["x-fastly-request-id"],
                confidence=95,
                description="Fastly tracking header present",
                reliability=EvidenceReliability.VERIFIED
            ))
        return evidence


class AkamaiSignature(TechnologySignature):
    @property
    def signature_id(self) -> str:
        return "akamai"

    @property
    def name(self) -> str:
        return "akamai"

    @property
    def category(self) -> TechnologyCategory:
        return TechnologyCategory.CDN

    def match(self, headers: dict, html: str, cookies: dict, scripts: List[str]) -> List[DetectionEvidence]:
        evidence = []
        server = headers.get("Server", "").lower()
        if "akamai" in server:
            evidence.append(DetectionEvidence(
                method=DetectionMethod.HEADER,
                source="Server",
                value="akamai",
                confidence=95,
                description="Akamai Server header present",
                reliability=EvidenceReliability.HIGH
            ))
        if "x-akamai-transformed" in headers or "x-akamai-request-id" in headers:
            evidence.append(DetectionEvidence(
                method=DetectionMethod.HEADER,
                source="Akamai Header",
                value="x-akamai-transformed",
                confidence=95,
                description="Akamai request headers present",
                reliability=EvidenceReliability.VERIFIED
            ))
        return evidence


class CloudFrontSignature(TechnologySignature):
    @property
    def signature_id(self) -> str:
        return "cloudfront"

    @property
    def name(self) -> str:
        return "cloudfront"

    @property
    def category(self) -> TechnologyCategory:
        return TechnologyCategory.CDN

    def match(self, headers: dict, html: str, cookies: dict, scripts: List[str]) -> List[DetectionEvidence]:
        evidence = []
        server = headers.get("Server", "").lower()
        if "cloudfront" in server:
            evidence.append(DetectionEvidence(
                method=DetectionMethod.HEADER,
                source="Server",
                value="cloudfront",
                confidence=95,
                description="CloudFront Server header present",
                reliability=EvidenceReliability.HIGH
            ))
        if "x-amz-cf-id" in headers or "x-amz-cf-pop" in headers:
            evidence.append(DetectionEvidence(
                method=DetectionMethod.HEADER,
                source="CloudFront Header",
                value="x-amz-cf-id",
                confidence=95,
                description="Amazon CloudFront custom headers present",
                reliability=EvidenceReliability.VERIFIED
            ))
        return evidence


class VercelSignature(TechnologySignature):
    @property
    def signature_id(self) -> str:
        return "vercel"

    @property
    def name(self) -> str:
        return "vercel"

    @property
    def category(self) -> TechnologyCategory:
        return TechnologyCategory.CDN

    def match(self, headers: dict, html: str, cookies: dict, scripts: List[str]) -> List[DetectionEvidence]:
        evidence = []
        server = headers.get("Server", "").lower()
        if "vercel" in server:
            evidence.append(DetectionEvidence(
                method=DetectionMethod.HEADER,
                source="Server",
                value="vercel",
                confidence=95,
                description="Vercel Server header present",
                reliability=EvidenceReliability.HIGH
            ))
        if "x-vercel-id" in headers or "x-vercel-cache" in headers:
            evidence.append(DetectionEvidence(
                method=DetectionMethod.HEADER,
                source="Vercel Header",
                value="x-vercel-id",
                confidence=95,
                description="Vercel deployment headers present",
                reliability=EvidenceReliability.VERIFIED
            ))
        return evidence


class NetlifySignature(TechnologySignature):
    @property
    def signature_id(self) -> str:
        return "netlify"

    @property
    def name(self) -> str:
        return "netlify"

    @property
    def category(self) -> TechnologyCategory:
        return TechnologyCategory.CDN

    def match(self, headers: dict, html: str, cookies: dict, scripts: List[str]) -> List[DetectionEvidence]:
        evidence = []
        server = headers.get("Server", "").lower()
        if "netlify" in server:
            evidence.append(DetectionEvidence(
                method=DetectionMethod.HEADER,
                source="Server",
                value="netlify",
                confidence=95,
                description="Netlify Server header present",
                reliability=EvidenceReliability.HIGH
            ))
        if "x-nf-request-id" in headers or "nf-request-id" in headers:
            evidence.append(DetectionEvidence(
                method=DetectionMethod.HEADER,
                source="Netlify Header",
                value="x-nf-request-id",
                confidence=95,
                description="Netlify custom request tracking headers present",
                reliability=EvidenceReliability.VERIFIED
            ))
        return evidence
