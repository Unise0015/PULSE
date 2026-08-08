import os
import pkgutil
import importlib
import inspect
import re
from pathlib import Path
from typing import List, Dict, Set, Type, Any, Optional
import logging
from pulse.ecosystems.base import EcosystemPlugin, PluginCategory, ScanContext, ScannerConfig, Capability, PluginHealth, PluginManifest
from pulse.domain.models import PackageInfo

class PluginRegistry:
    _loaded = False
    _manifests: Dict[str, PluginManifest] = {}
    _plugin_classes: Dict[str, Type[EcosystemPlugin]] = {}
    _registered_instances: List[EcosystemPlugin] = []

    @classmethod
    def register_class(cls, plugin: EcosystemPlugin):
        if not cls._loaded:
            cls._discover_and_cache()
        cls._manifests[plugin.manifest.id] = plugin.manifest
        cls._plugin_classes[plugin.manifest.id] = type(plugin)
        # Track registered instances
        if not hasattr(cls, "_registered_instances"):
            cls._registered_instances = []
        cls._registered_instances = [p for p in cls._registered_instances if p.manifest.id != plugin.manifest.id]
        cls._registered_instances.append(plugin)

    @classmethod
    def load(cls) -> List[EcosystemPlugin]:
        """Loads and instantiates fresh plugin instances per scan based on cached manifests."""
        if not cls._loaded:
            cls._discover_and_cache()
            
        plugins = []
        registered_instances = getattr(cls, "_registered_instances", [])
        registered_map = {p.manifest.id: p for p in registered_instances}
        
        for p_id in cls._manifests.keys():
            if p_id in registered_map:
                plugins.append(registered_map[p_id])
            else:
                plugin_cls = cls._plugin_classes[p_id]
                plugins.append(plugin_cls())
            
        return cls._topological_sort(plugins)

    @classmethod
    def _discover_and_cache(cls):
        seen_ids = set()
        seen_names = set()
        
        # Discover all directories containing a plugin.py under the ecosystems package
        pkg_dir = os.path.dirname(__file__)
        for _, subdir_name, is_pkg in pkgutil.iter_modules([pkg_dir]):
            if not is_pkg:
                continue
            
            plugin_module_path = f"pulse.ecosystems.{subdir_name}.plugin"
            try:
                module = importlib.import_module(plugin_module_path)
            except ModuleNotFoundError:
                continue
            
            for name, member in inspect.getmembers(module, inspect.isclass):
                if issubclass(member, EcosystemPlugin) and member is not EcosystemPlugin:
                    try:
                        plugin_instance = member()
                    except Exception as e:
                        raise ValueError(f"Failed to instantiate plugin class {name}: {e}")
                    
                    manifest = plugin_instance.manifest
                    
                    # --- Fast-Fail Startup Registry Validations ---
                    if not manifest.id:
                        raise ValueError(f"Plugin {name} must provide a non-empty manifest ID")
                    if not re.match(r"^[a-z0-9_]+$", manifest.id):
                        raise ValueError(f"Plugin {name} ID '{manifest.id}' must be lowercase alphanumeric/underscores")
                    if manifest.id in seen_ids:
                        raise ValueError(f"Duplicate plugin ID '{manifest.id}' detected")
                    if manifest.name in seen_names:
                        raise ValueError(f"Duplicate plugin display name '{manifest.name}' detected")
                    if not (0 <= manifest.priority <= 1000):
                        raise ValueError(f"Plugin {manifest.id} priority must be an integer between 0 and 1000")
                        
                    # --- Capability Consistency Validations ---
                    if Capability.GRAPH in manifest.capabilities:
                        # Ensure discover_dependency_edges is overridden
                        if member.discover_dependency_edges == EcosystemPlugin.discover_dependency_edges:
                            raise ValueError(f"Plugin {manifest.id} has GRAPH capability but did not implement discover_dependency_edges")
                    if Capability.LOCKFILE in manifest.capabilities:
                        if not hasattr(plugin_instance, "parse"):
                            raise ValueError(f"Plugin {manifest.id} has LOCKFILE capability but did not override parse method")
                            
                    if manifest.health == PluginHealth.DISABLED:
                        continue
                        
                    seen_ids.add(manifest.id)
                    seen_names.add(manifest.name)
                    cls._manifests[manifest.id] = manifest
                    cls._plugin_classes[manifest.id] = member
                    
        cls._loaded = True

    @classmethod
    def _topological_sort(cls, plugins: List[EcosystemPlugin]) -> List[EcosystemPlugin]:
        plugin_map = {p.manifest.id: p for p in plugins}
        visited: Dict[str, int] = {} # 0=visiting, 1=visited
        sorted_plugins = []

        def visit(p_id: str):
            if p_id not in plugin_map:
                return
            state = visited.get(p_id)
            if state == 0:
                raise ValueError(f"Circular dependency detected involving plugin '{p_id}'")
            if state == 1:
                return

            visited[p_id] = 0
            for dep_id in plugin_map[p_id].manifest.dependencies:
                visit(dep_id)
            visited[p_id] = 1
            sorted_plugins.append(plugin_map[p_id])

        for p in sorted(plugins, key=lambda x: x.manifest.priority, reverse=True):
            visit(p.manifest.id)

        return sorted_plugins

    @classmethod
    def reset(cls):
        cls._loaded = False
        cls._manifests = {}
        cls._plugin_classes = {}
        if hasattr(cls, "_registered_instances"):
            cls._registered_instances = []

    # --- Backward compatibility wrappers for registry object ---
    def register(self, plugin: EcosystemPlugin):
        self.__class__.register_class(plugin)

    def plugins(self) -> List[EcosystemPlugin]:
        return self.load()

    def get_all_providers(self) -> List[EcosystemPlugin]:
        return self.load()

    def detect(self, context_or_path: Any) -> List[EcosystemPlugin]:
        if isinstance(context_or_path, Path):
            context = ScanContext(root=context_or_path, config=ScannerConfig(), cache=None, history=None, logger=logging.getLogger())
        elif hasattr(context_or_path, "root") and not isinstance(context_or_path, Path):
            context = context_or_path
        else:
            context = ScanContext(root=Path(context_or_path), config=ScannerConfig(), cache=None, history=None, logger=logging.getLogger())
        return [p for p in self.load() if p.detect(context)]

    def discover(self, context_or_path: Any) -> List[PackageInfo]:
        if isinstance(context_or_path, Path):
            context = ScanContext(root=context_or_path, config=ScannerConfig(), cache=None, history=None, logger=logging.getLogger())
        elif hasattr(context_or_path, "root") and not isinstance(context_or_path, Path):
            context = context_or_path
        else:
            context = ScanContext(root=Path(context_or_path), config=ScannerConfig(), cache=None, history=None, logger=logging.getLogger())
        packages = []
        for plugin in self.detect(context):
            packages.extend(plugin.discover(context).packages)
        return packages
