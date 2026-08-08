import re
from typing import List, Optional
from pulse.domain.models import DetectionEvidence, DetectionMethod, TechnologyCategory, CPECandidate, EvidenceReliability
from pulse.website.signatures.base import TechnologySignature

class DjangoSignature(TechnologySignature):
    @property
    def signature_id(self) -> str:
        return "django"

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
        if "csrfmiddlewaretoken" in html:
            evidence.append(DetectionEvidence(
                method=DetectionMethod.HTML,
                source="HTML Body",
                value="csrfmiddlewaretoken",
                confidence=95,
                description="Django CSRF token input present in HTML",
                reliability=EvidenceReliability.HIGH
            ))
        if "django-debug-toolbar" in html:
            evidence.append(DetectionEvidence(
                method=DetectionMethod.HTML,
                source="HTML Body",
                value="django-debug-toolbar",
                confidence=95,
                description="Django debug toolbar wrapper found",
                reliability=EvidenceReliability.VERIFIED
            ))
        if "sessionid" in cookies:
            evidence.append(DetectionEvidence(
                method=DetectionMethod.COOKIE,
                source="Cookie Name",
                value="sessionid",
                confidence=85,
                description="Django session cookie sessionid detected",
                reliability=EvidenceReliability.MEDIUM
            ))
        return evidence

    def get_cpe_candidates(self, version: Optional[str]) -> List[CPECandidate]:
        ver = version if version else "*"
        return [CPECandidate(cpe=f"cpe:2.3:a:djangoproject:django:{ver}:*:*:*:*:*:*:*", confidence=95)]


class FlaskSignature(TechnologySignature):
    @property
    def signature_id(self) -> str:
        return "flask"

    @property
    def name(self) -> str:
        return "flask"

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
        server = headers.get("Server", "")
        if "werkzeug" in server.lower():
            evidence.append(DetectionEvidence(
                method=DetectionMethod.HEADER,
                source="Server",
                value=server,
                confidence=85,
                description="Flask backend detected via Werkzeug Server header",
                reliability=EvidenceReliability.HIGH
            ))
        return evidence

    def get_cpe_candidates(self, version: Optional[str]) -> List[CPECandidate]:
        ver = version if version else "*"
        return [CPECandidate(cpe=f"cpe:2.3:a:palletsprojects:flask:{ver}:*:*:*:*:*:*:*", confidence=95)]


class FastAPISignature(TechnologySignature):
    @property
    def signature_id(self) -> str:
        return "fastapi"

    @property
    def name(self) -> str:
        return "fastapi"

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
        if "swagger-ui" in html or "redoc.js" in html:
            evidence.append(DetectionEvidence(
                method=DetectionMethod.HTML,
                source="HTML Body",
                value="swagger-ui / redoc",
                confidence=70,
                description="FastAPI documentation assets (Swagger UI / ReDoc) found",
                reliability=EvidenceReliability.MEDIUM
            ))
        return evidence

    def get_cpe_candidates(self, version: Optional[str]) -> List[CPECandidate]:
        ver = version if version else "*"
        return [CPECandidate(cpe=f"cpe:2.3:a:tiangolo:fastapi:{ver}:*:*:*:*:*:*:*", confidence=95)]


class ExpressSignature(TechnologySignature):
    @property
    def signature_id(self) -> str:
        return "express"

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
        x_powered_by = headers.get("X-Powered-By", "")
        if "express" in x_powered_by.lower():
            evidence.append(DetectionEvidence(
                method=DetectionMethod.HEADER,
                source="X-Powered-By",
                value=x_powered_by,
                confidence=95,
                description="Express framework detected via X-Powered-By header",
                reliability=EvidenceReliability.VERIFIED
            ))
        return evidence

    def get_cpe_candidates(self, version: Optional[str]) -> List[CPECandidate]:
        ver = version if version else "*"
        return [CPECandidate(cpe=f"cpe:2.3:a:expressjs:express:{ver}:*:*:*:*:*:*:*", confidence=95)]


class NuxtSignature(TechnologySignature):
    @property
    def signature_id(self) -> str:
        return "nuxt"

    @property
    def name(self) -> str:
        return "nuxt.js"

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
        if "__NUXT__" in html:
            evidence.append(DetectionEvidence(
                method=DetectionMethod.HTML,
                source="HTML Body",
                value="__NUXT__",
                confidence=95,
                description="Nuxt.js page state global variables present",
                reliability=EvidenceReliability.VERIFIED
            ))
        if "data-n-head" in html or "id=\"__nuxt\"" in html or "nuxt" in html.lower():
            evidence.append(DetectionEvidence(
                method=DetectionMethod.HTML,
                source="HTML Body",
                value="data-n-head / __nuxt",
                confidence=85,
                description="Nuxt.js mounting point or document attributes found",
                reliability=EvidenceReliability.HIGH
            ))
        return evidence

    def get_cpe_candidates(self, version: Optional[str]) -> List[CPECandidate]:
        ver = version if version else "*"
        return [CPECandidate(cpe=f"cpe:2.3:a:nuxtjs:nuxt.js:{ver}:*:*:*:*:*:*:*", confidence=95)]
