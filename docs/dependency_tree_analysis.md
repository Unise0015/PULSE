# Dependency Tree Analysis & Supply Chain Exposure

CVE Scanner goes beyond flat vulnerability lists by mapping how vulnerabilities propagate through your dependency chains. This provides **Software Supply Chain Risk Assessment** capabilities completely offline.

## Core Concepts

### Direct vs. Transitive Dependencies
* **Direct Dependencies**: Packages your application explicitly requires (e.g., listed in `package.json` or `requirements.txt`).
* **Transitive Dependencies**: Packages that your direct dependencies require. You don't ask for them, but they are installed to make your direct dependencies work.

### Dependency Depth
The distance from your application to the vulnerable package.
* **Depth 0**: Direct dependency
* **Depth 1**: Transitive dependency (child of direct dependency)
* **Depth 2**: Transitive dependency (grandchild of direct dependency)

### Supply Chain Metrics
The scanner calculates several metrics to help you understand your exposure:
* **Vulnerable Direct**: Number of explicit dependencies containing vulnerabilities. These are typically the easiest to fix by bumping the version.
* **Vulnerable Transitive**: Number of implicit dependencies containing vulnerabilities. These often require waiting for the parent package to release an update or forcing a resolution.
* **Max Dependency Depth**: The deepest level of nested dependencies found in your project.

## How It Works

The platform builds dependency trees locally using native ecosystem metadata. It does **not** rely on external SaaS dependency graph services.

### Python
The scanner uses `importlib.metadata` to inspect the installed packages in the current environment and parses the `Requires-Dist` metadata.

### Node.js
The scanner reads `package-lock.json` (v2/v3) to reconstruct the exact resolved dependency tree, including all nested transitive dependencies.

### Flat Tree Fallback
For single-package scans (`--package`) or `requirements.txt` scans without an installed environment, the scanner falls back to a "flat tree" where all discovered packages are treated as isolated nodes.

## Viewing Dependency Trees

You can view the full dependency tree visually in the CLI using the interactive post-scan menu:

```
Post-Scan Actions:
  ...
  View Dependency Tree
```

Vulnerable packages and their CVE counts will be highlighted in **red**.

## SBOM Integration

The generated CycloneDX SBOM (`Export SBOM`) includes the `dependencies` array. This links each component's `bom-ref` to its direct dependencies, creating a machine-readable supply chain graph that can be ingested by standard SBOM analysis tools.
