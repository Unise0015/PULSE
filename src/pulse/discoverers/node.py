import json
import os
from pathlib import Path
from typing import List
from pulse.domain.models import PackageInfo
from pulse.discoverers.base import BaseDiscoverer

class NodeDiscoverer(BaseDiscoverer):
    """Discovers Node.js packages by parsing package.json and package-lock.json."""
    
    def discover(self, path: str = ".") -> List[PackageInfo]:
        packages = []
        target_dir = Path(path)
        
        package_json_path = target_dir / "package.json"
        package_lock_path = target_dir / "package-lock.json"
        
        # 1. Parse package.json for direct dependencies
        direct_deps = set()
        if package_json_path.exists():
            try:
                with open(package_json_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    
                    deps = data.get("dependencies", {})
                    dev_deps = data.get("devDependencies", {})
                    
                    for name in deps.keys():
                        direct_deps.add(name)
                    for name in dev_deps.keys():
                        direct_deps.add(name)
            except Exception:
                pass # Fail silently for discovery phase or log in future
                
        # 2. Parse package-lock.json for resolved versions (and transitives)
        if package_lock_path.exists():
            try:
                with open(package_lock_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    
                    # package-lock v2/v3 structure
                    packages_dict = data.get("packages", {})
                    if packages_dict:
                        for key, info in packages_dict.items():
                            if not key:
                                continue # Root project
                            
                            name = key.split("node_modules/")[-1]
                            version = info.get("version")
                            
                            if name and version:
                                dep_type = "DIRECT" if name in direct_deps else "TRANSITIVE"
                                packages.append(PackageInfo(
                                    name=name,
                                    version=version,
                                    ecosystem="npm",
                                    dependency_type=dep_type,
                                    reachability="UNKNOWN"
                                ))
                    else:
                        # package-lock v1 fallback
                        deps = data.get("dependencies", {})
                        for name, info in deps.items():
                            version = info.get("version")
                            if name and version:
                                dep_type = "DIRECT" if name in direct_deps else "TRANSITIVE"
                                packages.append(PackageInfo(
                                    name=name,
                                    version=version,
                                    ecosystem="npm",
                                    dependency_type=dep_type,
                                    reachability="UNKNOWN"
                                ))
            except Exception:
                pass
                
        return packages
