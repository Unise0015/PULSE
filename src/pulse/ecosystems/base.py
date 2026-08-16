from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import List, Dict, Set, Any, Optional
import logging
from pulse.domain.models import PackageInfo, DependencyEdge, PluginExecutionStatus, PluginDiagnostics

@dataclass
class DetectionCandidate:
    ecosystem: str
    confidence: int
    source: str

class PluginCategory(Enum):
    DEPENDENCY = "Dependency"
    WEBSITE = "Website"
    WORKFLOW = "Workflow"
    CONTAINER = "Container"
    INFRASTRUCTURE = "Infrastructure"
    SBOM = "SBOM"

class PluginHealth(Enum):
    SUPPORTED = "Supported"
    EXPERIMENTAL = "Experimental"
    DEPRECATED = "Deprecated"
    DISABLED = "Disabled"

class ScanPhase(Enum):
    DISCOVERY = "Discovery"
    PARSING = "Parsing"
    VALIDATION = "Validation"
    RESOLUTION = "Resolution"
    CORRELATION = "Correlation"
    ENRICHMENT = "Enrichment"
    SCORING = "Scoring"
    REPORTING = "Reporting"

class Capability(Enum):
    LOCKFILE = auto()
    REGISTRY = auto()
    GRAPH = auto()
    VERSION_RANGES = auto()
    REMEDIATION = auto()
    HISTORY = auto()

@dataclass
class ScannerConfig:
    default_severity: str = "high"
    default_output: str = "table"
    nvd_api_key: Optional[str] = None
    cache_duration_hours: int = 24
    offline_mode: bool = False
    verbose_mode: bool = False
    debug_mode: bool = False

@dataclass
class ScanContext:
    root: Path
    config: ScannerConfig = field(default_factory=ScannerConfig)
    cache: Any = None                 # Reference to SQLite Cache Service
    history: Any = None               # Reference to History Service
    logger: logging.Logger = field(default_factory=lambda: logging.getLogger("pulse.ecosystems"))
    event_bus: 'EventBus' = field(default_factory=lambda: EventBus())
    phase: ScanPhase = ScanPhase.DISCOVERY

@dataclass
class PluginCapabilities:
    lockfiles: bool
    dependency_graph: bool
    transitive_dependencies: bool
    version_ranges: bool
    registry_lookup: bool

@dataclass
class PluginManifest:
    id: str
    name: str
    ecosystem: str
    version: str = "1.0.0"
    priority: int = 0
    category: PluginCategory = PluginCategory.DEPENDENCY
    health: PluginHealth = PluginHealth.SUPPORTED
    capabilities: Set[Capability] = field(default_factory=set)
    dependencies: List[str] = field(default_factory=list)

@dataclass
class ProviderMetadata:
    ecosystem_id: str
    display_name: str
    registry_name: str
    package_manager: str = ""
    ecosystem_type: str = "application"  # application, system, infrastructure, container
    supports_version_lookup: bool = True
    supports_latest_version: bool = True
    osv_ecosystem: Optional[str] = None
    registry_url: Optional[str] = None


@dataclass
class RawDependency:

    name: str
    version_spec: str
    ecosystem: str
    dependency_type: str = "DIRECT"
    source_file: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ResolvedDependency:
    name: str
    resolved_version: str
    ecosystem: str
    dependency_type: str = "DIRECT"
    source_file: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)



@dataclass
class PluginMetrics:
    assets_scanned: int = 0
    files_parsed: int = 0
    packages_found: int = 0
    warnings: int = 0
    elapsed_ms: int = 0

@dataclass
class PluginResult:
    packages: List[PackageInfo]
    dependency_edges: List[DependencyEdge] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    metrics: PluginMetrics = field(default_factory=PluginMetrics)
    diagnostics: PluginDiagnostics = field(default_factory=lambda: PluginDiagnostics(PluginExecutionStatus.SUCCESS))

# --- Event Bus Core with Prioritization ---
class Event:
    pass

@dataclass
class DependencyDiscoveredEvent(Event):
    plugin_id: str
    dependencies: List[RawDependency]

@dataclass
class DependencyResolvedEvent(Event):
    plugin_id: str
    resolved: List[ResolvedDependency]

@dataclass
class PluginFinishedEvent(Event):
    plugin_id: str
    result: PluginResult

@dataclass
class PhaseChangedEvent(Event):
    old_phase: ScanPhase
    new_phase: ScanPhase

class EventBus:
    def __init__(self):
        # Maps event_type -> List of (handler, priority)
        self._subscribers: Dict[type, List[tuple]] = {}

    def subscribe(self, event_type: type, handler: Any, priority: int = 50):
        if event_type not in self._subscribers:
            self._subscribers[event_type] = []
        self._subscribers[event_type].append((handler, priority))
        # Sort subscribers by priority descending
        self._subscribers[event_type].sort(key=lambda item: item[1], reverse=True)

    def publish(self, event: Event):
        event_type = type(event)
        if event_type in self._subscribers:
            for handler, _ in self._subscribers[event_type]:
                try:
                    handler(event)
                except Exception:
                    pass

class EcosystemPlugin(ABC):
    @property
    @abstractmethod
    def manifest(self) -> PluginManifest:
        """Centralized plugin metadata configuration."""
        pass

    def _get_root(self, context: Any) -> Path:
        if isinstance(context, Path):
            return context
        if hasattr(context, "root") and not isinstance(context, Path):
            return context.root
        return Path(context)

    @abstractmethod
    def detect(self, context: ScanContext) -> bool:
        """Check if this plugin targets the current workspace context."""
        pass

    def discover_assets(self, context: ScanContext) -> List[Any]:
        """Perform initial asset scanner hooks (e.g. locating files, workflows, containers)."""
        return []

    @abstractmethod
    def parse(self, context: ScanContext) -> List[RawDependency]:
        """Parse configuration files or locate assets to extract raw dependencies."""
        pass

    def validate(self, raw_dependencies: List[RawDependency], context: ScanContext) -> List[RawDependency]:
        """Perform syntax or validation checks on raw dependencies before resolution."""
        return raw_dependencies

    @abstractmethod
    def resolve(self, raw_dependencies: List[RawDependency], context: ScanContext) -> List[ResolvedDependency]:
        """Perform version resolution or registry/transitive expansion."""
        pass

    @abstractmethod
    def normalize(self, resolved_dependencies: List[ResolvedDependency], context: ScanContext) -> List[PackageInfo]:
        """Convert resolved raw structures to unified PackageInfo models."""
        pass

    def discover(self, context: ScanContext) -> PluginResult:
        """Standardized orchestrator calling the lifecycle execution stages."""
        import time
        start_time = time.time()
        
        warnings = []
        errors = []
        raw = []
        validated = []
        resolved = []
        packages = []
        edges = []
        
        # 1. Discover Assets
        try:
            self.discover_assets(context)
        except Exception as e:
            msg = f"Asset discovery failed: {e}"
            errors.append(msg)
            logging.getLogger("pulse").error(f"Plugin {self.manifest.id} asset discovery failed: {e}", exc_info=True)
            
        # 2. Parse Manifests
        try:
            raw = self.parse(context)
            context.event_bus.publish(DependencyDiscoveredEvent(self.manifest.id, raw))
        except Exception as e:
            msg = f"Parsing failed: {e}"
            errors.append(msg)
            logging.getLogger("pulse").error(f"Plugin {self.manifest.id} parsing failed: {e}", exc_info=True)
            
        # 3. Validate raw dependencies
        if raw and not errors:
            try:
                validated = self.validate(raw, context)
            except Exception as e:
                msg = f"Validation failed: {e}"
                warnings.append(msg)
                logging.getLogger("pulse").error(f"Plugin {self.manifest.id} validation failed: {e}", exc_info=True)
                validated = raw # fallback
        else:
            validated = raw
            
        # 4. Resolve dependencies
        if validated and not errors:
            try:
                resolved = self.resolve(validated, context)
                context.event_bus.publish(DependencyResolvedEvent(self.manifest.id, resolved))
            except Exception as e:
                msg = f"Resolution failed: {e}"
                errors.append(msg)
                logging.getLogger("pulse").error(f"Plugin {self.manifest.id} resolution failed: {e}", exc_info=True)
                # Fallback: convert to resolved directly
                resolved = [ResolvedDependency(r.name, r.version_spec, r.ecosystem, r.dependency_type, r.source_file, r.metadata) for r in validated]
        else:
            # If parsing failed, resolved is empty
            pass
            
        # 5. Normalize resolved packages
        if resolved:
            try:
                packages = self.normalize(resolved, context)
            except Exception as e:
                msg = f"Normalization failed: {e}"
                errors.append(msg)
                logging.getLogger("pulse").error(f"Plugin {self.manifest.id} normalization failed: {e}", exc_info=True)
                
        # 6. Discover dependency edges
        try:
            edges = self.discover_dependency_edges(context.root)
        except Exception as e:
            msg = f"Dependency edges lookup failed: {e}"
            warnings.append(msg)
            logging.getLogger("pulse").error(f"Plugin {self.manifest.id} edges lookup failed: {e}", exc_info=True)
            
        elapsed = int((time.time() - start_time) * 1000)
        
        # Determine status
        if errors:
            status = PluginExecutionStatus.FAILED
        elif warnings:
            status = PluginExecutionStatus.WARNING
        else:
            status = PluginExecutionStatus.SUCCESS
            
        diagnostics = PluginDiagnostics(
            status=status,
            warnings=warnings,
            errors=errors,
            duration_ms=elapsed
        )
        
        metrics = PluginMetrics(
            assets_scanned=len(packages),
            files_parsed=1,
            packages_found=len(packages),
            warnings=len(warnings) + len(errors),
            elapsed_ms=elapsed
        )
        
        result = PluginResult(
            packages=packages,
            dependency_edges=edges,
            warnings=warnings + errors,
            metrics=metrics,
            diagnostics=diagnostics
        )
        context.event_bus.publish(PluginFinishedEvent(self.manifest.id, result))
        return result

    # --- Optional Lifecycle Hooks ---
    def initialize(self, context: ScanContext) -> None:
        """Optional plugin setup hook."""
        pass

    def before_scan(self, context: ScanContext) -> None:
        """Hook called before the scanning process begins."""
        pass

    def after_scan(self, context: ScanContext) -> None:
        """Hook called immediately after scan completions."""
        pass

    def shutdown(self) -> None:
        """Hook for plugin cleanup and resource shutdown."""
        pass

    # --- Backward compatibility utility hooks ---
    def discover_dependency_edges(self, root: Path) -> List[DependencyEdge]:
        return []

    def package_name_confidence(self, name: str) -> int:
        return 0

    @property
    def display_name(self) -> str:
        """Human-readable ecosystem display name (e.g. 'Python', 'Node.js')."""
        return self.manifest.name

    @property
    def registry_name(self) -> str:
        """Human-readable registry name (e.g. 'PyPI', 'npm', 'crates.io')."""
        # Import here to avoid circular; the map is defined below EcosystemPlugin
        from pulse.ecosystems.base import ECOSYSTEM_REGISTRY_MAP
        return ECOSYSTEM_REGISTRY_MAP.get(self.manifest.name, self.manifest.ecosystem or self.manifest.name)

    @property
    def provider_metadata(self) -> ProviderMetadata:
        """Canonical metadata for ecosystem provider."""
        return ProviderMetadata(
            ecosystem_id=self.manifest.id,
            display_name=self.display_name,
            registry_name=self.registry_name,
            osv_ecosystem=self.manifest.ecosystem
        )

    def normalize_package_name(self, name: str) -> str:
        return name.strip()

    def package_exists(self, package_name: str) -> bool:
        return False

    def version_exists(self, package_name: str, version: str) -> bool:
        return False

    def get_latest_version(self, package_name: str) -> Optional[str]:
        return None

    async def validate_registry_async(self, client: Any, name: str, version: Optional[str] = None) -> Any:
        return None


    def discover_packages(self, path: Path) -> List[PackageInfo]:
        from pulse.ecosystems.base import ScanContext, ScannerConfig
        import logging
        ctx = ScanContext(root=path, config=ScannerConfig(), cache=None, history=None, logger=logging.getLogger())
        return self.discover(ctx).packages


# --- Ecosystem-to-Registry Display Name Mapping ---
ECOSYSTEM_REGISTRY_MAP = {
    "Python": "PyPI",
    "Node.js": "npm",
    "Rust": "crates.io",
    "Go": "Go Modules",
    "Ruby": "RubyGems",
    "Composer": "Packagist",
    "NuGet": "NuGet",
    "Maven": "Maven Central",
    "Swift": "Swift Package Index",
    "Dart": "pub.dev",
    "Hex": "Hex.pm",
    "CRAN": "CRAN",
    "Clojars": "Clojars",
    "Hackage": "Hackage",
    "CPAN": "CPAN",
    "Conan": "ConanCenter",
    "Terraform": "Terraform Registry",
    "Helm": "Helm Charts",
    "Alpine": "Alpine Packages",
    "Debian": "Debian Security Tracker",
    "Ubuntu": "Ubuntu Security Notices",
    "RPM": "Fedora/RHEL Security",
    "Arch": "Arch Package Database",
    "Nix": "Nixpkgs",
    "Container": "Docker/OCI Registries"
}


# --- Legacy Compatibility Wrapper ---
class EcosystemProvider(EcosystemPlugin):
    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if "detect" in cls.__dict__:
            orig_detect = cls.__dict__["detect"]
            if not getattr(orig_detect, "_is_wrapped", False):
                def wrapped_detect(self, context_or_path: Any) -> bool:
                    if isinstance(context_or_path, Path):
                        return orig_detect(self, context_or_path)
                    root = self._get_root(context_or_path)
                    return orig_detect(self, root)
                wrapped_detect._is_wrapped = True
                cls.detect = wrapped_detect

    @property
    def manifest(self) -> PluginManifest:
        # Construct a default manifest based on legacy properties
        return PluginManifest(
            id=self.ecosystem_name.lower().replace(".", ""),
            name=self.ecosystem_name,
            ecosystem=self.osv_ecosystem
        )

    @property
    @abstractmethod
    def ecosystem_name(self) -> str:
        pass

    @property
    @abstractmethod
    def osv_ecosystem(self) -> str:
        pass

    @property
    def display_name(self) -> str:
        """Human-readable ecosystem display name (e.g. 'Python', 'Node.js')."""
        return self.manifest.name

    @property
    def registry_name(self) -> str:
        """Human-readable registry name (e.g. 'PyPI', 'npm', 'crates.io')."""
        return ECOSYSTEM_REGISTRY_MAP.get(self.manifest.name, self.manifest.ecosystem)

    def detect(self, context_or_path: Any) -> bool:
        if isinstance(context_or_path, Path):
            return self.detect_legacy(context_or_path)
        return self.detect_legacy(context_or_path.root)

    def detect_legacy(self, path: Path) -> bool:
        return False

    def parse(self, context: ScanContext) -> List[RawDependency]:
        pkgs = self.discover_packages(context.root)
        raw_deps = []
        for p in pkgs:
            raw_deps.append(RawDependency(
                name=p.name,
                version_spec=p.version,
                ecosystem=p.ecosystem,
                dependency_type=p.dependency_type,
                source_file=p.source_file,
                metadata=p.metadata
            ))
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
        pkgs = []
        for r in resolved_dependencies:
            pkgs.append(PackageInfo(
                name=r.name,
                version=r.resolved_version,
                ecosystem=r.ecosystem,
                dependency_type=r.dependency_type,
                source_file=r.source_file,
                metadata=r.metadata
            ))
        return pkgs

    def discover_packages(self, path: Path) -> List[PackageInfo]:
        return []

    # Also map discover_dependency_edges back to Legacy expect Path
    def discover_dependency_edges(self, root: Path) -> List[DependencyEdge]:
        return self.discover_dependency_edges_legacy(root)

    def discover_dependency_edges_legacy(self, root: Path) -> List[DependencyEdge]:
        return []

def __getattr__(name):
    if name == "EcosystemRegistry":
        from pulse.ecosystems.registry import PluginRegistry
        return PluginRegistry
    raise AttributeError(f"module {__name__} has no attribute {name}")
