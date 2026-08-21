from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from pulse.domain.models import PackageInfo

@dataclass
class HostSystemMetadata:
    os_name: str = "Unknown"
    os_family: str = "linux"
    distro_id: str = "unknown"
    distro_version: str = "unknown"
    kernel_release: str = "unknown"
    architecture: str = "unknown"
    package_manager: str = "unknown"
    total_packages: int = 0
    extra: Dict[str, Any] = field(default_factory=dict)

class BaseHostDiscoverer(ABC):
    """Abstract interface for host-level OS and software discovery."""

    @abstractmethod
    def is_applicable(self) -> bool:
        """Returns True if this discoverer is applicable to the current host OS."""
        pass

    @abstractmethod
    def get_metadata(self) -> HostSystemMetadata:
        """Extracts operating system and kernel metadata."""
        pass

    @abstractmethod
    def discover(self) -> List[PackageInfo]:
        """Discovers all installed host packages and the kernel."""
        pass
