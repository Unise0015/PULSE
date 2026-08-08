from typing import List, Optional
from pulse.domain.models import DetectionEvidence, DetectionMethod, TechnologyCategory, CPECandidate, EvidenceReliability
from pulse.website.signatures.base import TechnologySignature

class ExpressCookieSignature(TechnologySignature):
    @property
    def signature_id(self) -> str:
        return "express_cookie"

    @property
    def name(self) -> str:
        return "express"

    @property
    def category(self) -> TechnologyCategory:
        return TechnologyCategory.FRAMEWORK

    @property
    def ecosystem(self) -> Optional[str]:
        return "npm"

    @property
    def correlation_supported(self) -> bool:
        return True

    def match(self, headers: dict, html: str, cookies: dict, scripts: List[str]) -> List[DetectionEvidence]:
        evidence = []
        if "connect.sid" in cookies:
            evidence.append(DetectionEvidence(
                method=DetectionMethod.COOKIE,
                source="Cookie Name",
                value="connect.sid",
                confidence=95,
                description="Express session cookie connect.sid detected",
                reliability=EvidenceReliability.HIGH
            ))
        return evidence

    def get_cpe_candidates(self, version: Optional[str]) -> List[CPECandidate]:
        return [CPECandidate(cpe="cpe:2.3:a:expressjs:express:*:*:*:*:*:*:*:*", confidence=80)]


class PhpSessionCookieSignature(TechnologySignature):
    @property
    def signature_id(self) -> str:
        return "php_cookie"

    @property
    def name(self) -> str:
        return "php"

    @property
    def category(self) -> TechnologyCategory:
        return TechnologyCategory.RUNTIME

    def match(self, headers: dict, html: str, cookies: dict, scripts: List[str]) -> List[DetectionEvidence]:
        evidence = []
        if "PHPSESSID" in cookies:
            evidence.append(DetectionEvidence(
                method=DetectionMethod.COOKIE,
                source="Cookie Name",
                value="PHPSESSID",
                confidence=90,
                description="PHP session cookie PHPSESSID detected",
                reliability=EvidenceReliability.HIGH
            ))
        return evidence

    def get_cpe_candidates(self, version: Optional[str]) -> List[CPECandidate]:
        return [CPECandidate(cpe="cpe:2.3:a:php:php:*:*:*:*:*:*:*:*", confidence=80)]


class JavaSessionCookieSignature(TechnologySignature):
    @property
    def signature_id(self) -> str:
        return "java_cookie"

    @property
    def name(self) -> str:
        return "java"

    @property
    def category(self) -> TechnologyCategory:
        return TechnologyCategory.RUNTIME

    def match(self, headers: dict, html: str, cookies: dict, scripts: List[str]) -> List[DetectionEvidence]:
        evidence = []
        if "JSESSIONID" in cookies:
            evidence.append(DetectionEvidence(
                method=DetectionMethod.COOKIE,
                source="Cookie Name",
                value="JSESSIONID",
                confidence=90,
                description="Java servlet session cookie JSESSIONID detected",
                reliability=EvidenceReliability.HIGH
            ))
        return evidence

    def get_cpe_candidates(self, version: Optional[str]) -> List[CPECandidate]:
        return [CPECandidate(cpe="cpe:2.3:a:oracle:jre:*:*:*:*:*:*:*:*", confidence=60)]


class AspNetSessionCookieSignature(TechnologySignature):
    @property
    def signature_id(self) -> str:
        return "aspnet_cookie"

    @property
    def name(self) -> str:
        return "asp.net"

    @property
    def category(self) -> TechnologyCategory:
        return TechnologyCategory.FRAMEWORK

    def match(self, headers: dict, html: str, cookies: dict, scripts: List[str]) -> List[DetectionEvidence]:
        evidence = []
        # ASPSESSIONID or ASP.NET_SessionId
        found = [c for c in cookies if "ASPSESSIONID" in c or c == "ASP.NET_SessionId"]
        if found:
            evidence.append(DetectionEvidence(
                method=DetectionMethod.COOKIE,
                source="Cookie Name",
                value=found[0],
                confidence=95,
                description=f"ASP.NET session cookie {found[0]} detected",
                reliability=EvidenceReliability.HIGH
            ))
        return evidence

    def get_cpe_candidates(self, version: Optional[str]) -> List[CPECandidate]:
        return [CPECandidate(cpe="cpe:2.3:a:microsoft:asp.net:*:*:*:*:*:*:*:*", confidence=80)]


class DjangoSessionCookieSignature(TechnologySignature):
    @property
    def signature_id(self) -> str:
        return "django_cookie"

    @property
    def name(self) -> str:
        return "django"

    @property
    def category(self) -> TechnologyCategory:
        return TechnologyCategory.FRAMEWORK

    @property
    def ecosystem(self) -> Optional[str]:
        return "PyPI"

    @property
    def correlation_supported(self) -> bool:
        return True

    def match(self, headers: dict, html: str, cookies: dict, scripts: List[str]) -> List[DetectionEvidence]:
        evidence = []
        if "sessionid" in cookies and "csrftoken" in cookies:
            evidence.append(DetectionEvidence(
                method=DetectionMethod.COOKIE,
                source="Cookie Name",
                value="sessionid & csrftoken",
                confidence=85,
                description="Django session and CSRF cookies detected",
                reliability=EvidenceReliability.HIGH
            ))
        return evidence

    def get_cpe_candidates(self, version: Optional[str]) -> List[CPECandidate]:
        return [CPECandidate(cpe="cpe:2.3:a:djangoproject:django:*:*:*:*:*:*:*:*", confidence=80)]
