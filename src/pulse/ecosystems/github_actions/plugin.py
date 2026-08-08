import re
from pathlib import Path
from typing import List
from pulse.domain.models import PackageInfo
from pulse.ecosystems.base import EcosystemPlugin, PluginManifest, ScanContext, RawDependency, ResolvedDependency, Capability, PluginCategory

class GitHubActionsPlugin(EcosystemPlugin):
    @property
    def manifest(self) -> PluginManifest:
        return PluginManifest(
            id="github_actions",
            name="GitHub Actions",
            ecosystem="GitHub Actions",
            priority=50,
            category=PluginCategory.WORKFLOW,
            capabilities={Capability.LOCKFILE}
        )

    def detect(self, context: ScanContext) -> bool:
        root = self._get_root(context)
        workflow_dir = root / ".github" / "workflows"
        if not workflow_dir.exists():
            return False
        return len(list(workflow_dir.glob("*.yml"))) > 0 or len(list(workflow_dir.glob("*.yaml"))) > 0

    def parse(self, context: ScanContext) -> List[RawDependency]:
        root = self._get_root(context)
        raw_deps = []
        workflow_dir = root / ".github" / "workflows"
        if not workflow_dir.exists():
            return raw_deps
            
        workflow_files = list(workflow_dir.glob("*.yml")) + list(workflow_dir.glob("*.yaml"))
        pattern = re.compile(r"uses:\s*[\"']?([a-zA-Z0-9_\-\./]+)@([a-zA-Z0-9_\-\./\+]+)[\"']?")
        
        for wf_path in workflow_files:
            try:
                content = wf_path.read_text(encoding="utf-8")
                for line in content.splitlines():
                    match = pattern.search(line)
                    if match:
                        action_name = match.group(1).strip()
                        version_spec = match.group(2).strip()
                        
                        # Filter out local references and docker actions
                        if action_name.startswith("./") or action_name.startswith("docker://"):
                            continue
                            
                        raw_deps.append(RawDependency(
                            name=action_name,
                            version_spec=version_spec,
                            ecosystem="GitHub Actions",
                            dependency_type="DIRECT",
                            source_file=str(wf_path)
                        ))
            except Exception:
                pass
        return raw_deps

    def resolve(self, raw_dependencies: List[RawDependency], context: ScanContext) -> List[ResolvedDependency]:
        resolved = []
        for r in raw_dependencies:
            resolved.append(ResolvedDependency(
                name=r.name,
                resolved_version=r.version_spec,
                ecosystem=r.ecosystem,
                dependency_type=r.dependency_type,
                source_file=r.source_file,
                metadata=r.metadata
            ))
        return resolved

    def normalize(self, resolved_dependencies: List[ResolvedDependency], context: ScanContext) -> List[PackageInfo]:
        packages = []
        for r in resolved_dependencies:
            packages.append(PackageInfo(
                name=r.name,
                version=r.resolved_version,
                ecosystem="GitHub Actions",
                dependency_type=r.dependency_type,
                source_file=r.source_file,
                metadata=r.metadata
            ))
        return packages
