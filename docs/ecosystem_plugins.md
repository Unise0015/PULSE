# Ecosystem Plugin Architecture

The CVE Scanner framework utilizes a plugin-based architecture to scan and analyze software assets and dependencies. Each ecosystem plugin is a self-contained module that plugs into the scanner's lifecycle, discovers dependencies, and exposes metadata to downstream vulnerability analysis services.

---

## Architecture Pipeline

The scanning process is divided into separate, decoupled stages defined by the `ScanPhase` enum:

```text
               ScanContext
                    │
                    ▼
           Plugin Registry Load
                    │
           Topological Sorting
                    │
            [For Each Plugin]
                    │
       ┌────────────┴────────────┐
       │   Asset Discovery       │
       │         │               │
       │   Dependency Parsing    │ (RawDependency)
       │         │               │
       │   Dependency Validation │ (RawDependency)
       │         │               │
       │   Dependency Resolution │ (ResolvedDependency)
       │         │               │
       │   Normalization         │ (PackageInfo)
       └────────────┬────────────┘
                    │
                    ▼
          Version Intelligence
                    │
          Vulnerability Correlation (OSV / NVD / KEV)
                    │
          Threat Enrichment & Scoring
                    │
             Risk Calculation
                    │
                Reporting
```

---

## 1. Key Interface Models

### ScanContext
Every plugin stage receives a `ScanContext` containing standard state services:
- `root`: The Path of the project root workspace directory.
- `config`: A typed `ScannerConfig` option class.
- `cache`: An instance of the internal cache database adapter.
- `history`: Access to posture scan history and deltas.
- `logger`: Logging instance.
- `event_bus`: Decoupled publisher.
- `phase`: Current `ScanPhase` enum stage.

### PluginManifest
Standard metadata configuration exposing plugin limits:
- `id`: Unique lowercase identifier (e.g. `python`).
- `name`: Friendly display name (e.g. `Python`).
- `ecosystem`: Target registry ecosystem name (e.g. `PyPI`).
- `priority`: Order priority weight rank (0-1000).
- `category`: `PluginCategory` group (e.g. `DEPENDENCY`, `WORKFLOW`).
- `health`: Plugin lifecycle state (`SUPPORTED`, `EXPERIMENTAL`, `DEPRECATED`, `DISABLED`).
- `capabilities`: Set of `Capability` enum flags.
- `dependencies`: List of other plugins that must execute before this plugin.

---

## 2. Dynamic Registry Discovery

Plugins are discovered automatically at startup. The `PluginRegistry` scans folders under `cve_scanner/ecosystems/` using `pkgutil.iter_modules()` for submodules containing a `plugin.py` file.

### Topological Sorting
To resolve execution ordering, plugins are sorted topologically based on the `dependencies` defined in their manifest. If a circular dependency is detected, the registry raises a startup validation error.

---

## 3. Creating a New Plugin

To add a new ecosystem plugin:

1. Create a new directory under `src/cve_scanner/ecosystems/<your_ecosystem>/`.
2. Add an empty `__init__.py` file.
3. Create a `plugin.py` exposing a class subclassing `EcosystemPlugin`:

```python
from pathlib import Path
from typing import List
from cve_scanner.domain.models import PackageInfo
from cve_scanner.ecosystems.base import EcosystemPlugin, PluginManifest, ScanContext, RawDependency, ResolvedDependency, Capability, PluginCategory

class MyEcosystemPlugin(EcosystemPlugin):
    @property
    def manifest(self) -> PluginManifest:
        return PluginManifest(
            id="my_ecosystem",
            name="My Ecosystem",
            ecosystem="my-registry",
            priority=50,
            category=PluginCategory.DEPENDENCY,
            capabilities={Capability.LOCKFILE}
        )

    def detect(self, context: ScanContext) -> bool:
        root = self._get_root(context)
        return (root / "manifest.json").exists()

    def parse(self, context: ScanContext) -> List[RawDependency]:
        root = self._get_root(context)
        # Parse manifest and yield RawDependency elements
        return [RawDependency(name="pkg", version_spec="1.0.0", ecosystem="my-registry")]

    def resolve(self, raw: List[RawDependency], context: ScanContext) -> List[ResolvedDependency]:
        # Perform local expansion or fallback copy:
        return [ResolvedDependency(name=r.name, resolved_version=r.version_spec, ecosystem=r.ecosystem) for r in raw]

    def normalize(self, resolved: List[ResolvedDependency], context: ScanContext) -> List[PackageInfo]:
        return [PackageInfo(name=r.name, version=r.resolved_version, ecosystem="my-registry") for r in resolved]
```

---

## 4. Prioritized Event Bus

The core scan pipeline leverages a prioritized `EventBus` to notify telemetry, metrics, history delta services, and console UI managers of scan milestones:
- `DependencyDiscoveredEvent`
- `DependencyResolvedEvent`
- `PluginFinishedEvent`
- `PhaseChangedEvent`

Subscribers register with a specific priority score (higher execution rank runs first).
