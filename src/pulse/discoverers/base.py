from abc import ABC, abstractmethod
from typing import List
from pulse.domain.models import PackageInfo

class BaseDiscoverer(ABC):
    """Base class for all dependency discoverers."""
    
    @abstractmethod
    def discover(self, path: str = ".") -> List[PackageInfo]:
        """Discover installed dependencies and return a list of PackageInfo objects.
        
        Args:
            path (str): The path to the project to scan. Defaults to current directory.
            
        Returns:
            List[PackageInfo]: A list of discovered packages.
        """
        pass
