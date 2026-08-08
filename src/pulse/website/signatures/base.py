from abc import ABC, abstractmethod
from typing import List, Optional
from pulse.domain.models import DetectionEvidence, TechnologyCategory, CPECandidate

class TechnologySignature(ABC):
    @property
    @abstractmethod
    def signature_id(self) -> str:
        """Unique stable identifier for the signature (e.g., 'react')."""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name of the technology (e.g., 'React')."""
        pass

    @property
    @abstractmethod
    def category(self) -> TechnologyCategory:
        """Category of the technology."""
        pass

    @property
    def priority(self) -> int:
        """Priority of execution (lower priority runs later/earlier, standard 50)."""
        return 50

    @property
    def signature_version(self) -> str:
        """Version of this signature definition."""
        return "1.0"

    @property
    def provides_version(self) -> bool:
        """Flag indicating if this signature can extract version information."""
        return False

    @property
    def supports_relationships(self) -> bool:
        """Flag indicating if this signature supports relationship tracking (e.g., parent link)."""
        return False

    @property
    def provides_cpe_candidates(self) -> bool:
        """Flag indicating if this signature can map to CPE candidates."""
        return False

    @property
    def minimum_matches(self) -> int:
        """Minimum unique evidence matches required to verify detection."""
        return 1

    @property
    def parent_id(self) -> Optional[str]:
        """The signature ID of the parent technology if applicable."""
        return None

    @property
    def ecosystem(self) -> Optional[str]:
        """Ecosystem name if this technology correlates to a package manager package (e.g. npm)."""
        return None

    @property
    def correlation_supported(self) -> bool:
        """Whether this technology supports package vulnerability correlation."""
        return False

    @abstractmethod
    def match(self, headers: dict, html: str, cookies: dict, scripts: List[str]) -> List[DetectionEvidence]:
        """Perform passive matching logic on response components and return list of evidence found."""
        pass

    def extract_version(self, headers: dict, html: str, cookies: dict, scripts: List[str]) -> Optional[str]:
        """Extract version string if provides_version is True."""
        return None

    def get_cpe_candidates(self, version: Optional[str]) -> List[CPECandidate]:
        """Generate a list of CPE candidate mappings for future vulnerability correlation."""
        return []
