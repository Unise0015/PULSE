# Supported Package Ecosystems & Plugin Architecture

PULSE utilizes a modular plugin architecture to discover, parse, resolve, and normalize software dependencies across **14+ package ecosystems**.

---

## 1. Supported Ecosystems Reference

| Ecosystem | Registry | Default Manifest / Lockfiles | Resolver Mechanism |
| :--- | :--- | :--- | :--- |
| **Python** | PyPI | `requirements.txt`, `Pipfile(.lock)`, `poetry.lock`, `pyproject.toml`, `setup.py` | PyPI JSON API / AST Parser |
| **Node.js** | npm | `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` | npm Registry API / AST Parser |
| **Rust** | crates.io | `Cargo.toml`, `Cargo.lock` | Crates.io API / TOML Parser |
| **Go** | Go Modules | `go.mod`, `go.sum` | Go Proxy API / Parser |
| **Ruby** | RubyGems | `Gemfile`, `Gemfile.lock` | RubyGems API / Lockfile Parser |
| **PHP** | Packagist | `composer.json`, `composer.lock` | Packagist API / Composer Parser |
| **Java** | Maven Central | `pom.xml`, `build.gradle` | Maven Search API / XML Parser |
| **.NET / C#** | NuGet | `*.csproj`, `packages.config`, `paket.lock` | NuGet v3 API / XML Parser |
| **Dart / Flutter** | pub.dev | `pubspec.yaml`, `pubspec.lock` | Pub Registry API / YAML Parser |
| **Elixir** | Hex.pm | `mix.exs`, `mix.lock` | Hex API / Mix Parser |
| **C / C++** | Conan Center | `conanfile.txt`, `conanfile.py` | Conan Center API / Parser |
| **Swift** | SwiftPM | `Package.swift`, `Package.resolved` | SwiftPM Manifest Parser |
| **GitHub Actions** | GitHub | `.github/workflows/*.yml`, `action.yml` | Workflow AST & Tag Parser |
| **Containers** | Docker / OCI | `Dockerfile`, container image tags | Dockerfile AST & Registry API |

---

## 2. Plugin Lifecycle (`EcosystemPlugin`)

Each plugin implements the `EcosystemPlugin` interface:

```python
from pathlib import Path
from typing import List
from pulse.domain.models import PackageInfo
from pulse.ecosystems.base import EcosystemPlugin, PluginManifest, ScanContext, RawDependency, ResolvedDependency

class CustomEcosystemPlugin(EcosystemPlugin):
    @property
    def manifest(self) -> PluginManifest:
        return PluginManifest(id="custom", name="Custom Ecosystem", ecosystem="custom-registry")

    def detect(self, context: ScanContext) -> bool:
        return (context.root / "manifest.json").exists()

    def parse(self, context: ScanContext) -> List[RawDependency]:
        # Extract dependency names and versions
        ...

    def resolve(self, raw: List[RawDependency], context: ScanContext) -> List[ResolvedDependency]:
        # Validate versions against registry
        ...

    def normalize(self, resolved: List[ResolvedDependency], context: ScanContext) -> List[PackageInfo]:
        # Convert to canonical PackageInfo
        ...
```\n