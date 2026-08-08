import importlib.metadata
from typing import List
from pulse.domain.models import PackageInfo
from pulse.discoverers.base import BaseDiscoverer

class PythonDiscoverer(BaseDiscoverer):
    """Discovers Python packages installed in the current environment."""
    
    def discover(self, path: str = ".") -> List[PackageInfo]:
        packages = []
        
        # Currently, this inspects the environment where PULSE is running.
        # Future enhancements can parse requirements.txt, poetry.lock, Pipfile.lock in `path`.
        distributions = importlib.metadata.distributions()
        
        for dist in distributions:
            name = dist.metadata.get('Name')
            version = dist.version
            if name and version:
                packages.append(PackageInfo(
                    name=name,
                    version=version,
                    ecosystem="python",
                    dependency_type="DIRECT", # We default to DIRECT unless we have a dep graph
                    reachability="UNKNOWN"
                ))
                
        return packages
