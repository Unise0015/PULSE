from pathlib import Path
from typing import List
from pulse.domain.models import PackageInfo, DependencyEdge
from pulse.ecosystems.python.plugin import PythonPlugin

class PythonProvider(PythonPlugin):
    @property
    def ecosystem_name(self) -> str:
        return self.manifest.name

    @property
    def osv_ecosystem(self) -> str:
        return self.manifest.ecosystem

    def discover_packages(self, path: Path) -> List[PackageInfo]:
        from pulse.ecosystems.base import ScanContext, ScannerConfig
        import logging
        ctx = ScanContext(root=path, config=ScannerConfig(), cache=None, history=None, logger=logging.getLogger())
        return self.discover(ctx).packages

    def discover_dependency_edges_legacy(self, root: Path) -> List[DependencyEdge]:
        return self.discover_dependency_edges(root)
