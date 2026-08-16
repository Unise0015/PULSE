# PULSE System Architecture & Component Design

PULSE (Package & Unified Lifecycle Security Engine) is an enterprise-grade vulnerability intelligence and attack surface analysis platform. It features a decoupled, modular architecture designed for high throughput, local offline resilience, and actionable remediation insights.

---

## 1. High-Level Architecture

```
                       ┌────────────────────────────────────────────────────────┐
                       │                       PULSE CLI                        │
                       │             (Interactive TUI & CLI Runner)             │
                       └───────────────┬────────────────────────┬───────────────┘
                                       │                        │
                 ┌─────────────────────┴──────────┐  ┌──────────┴─────────────────────┐
                 │       Package Discovery        │  │      Website Fingerprinting    │
                 │   14+ Ecosystems & Lockfiles   │  │   3,000+ Declarative Signatures│
                 └─────────────────────┬──────────┘  └──────────┬─────────────────────┘
                                       │                        │
                                       └───────────┬────────────┘
                                                   ▼
                                ┌──────────────────────────────────────┐
                                │     Canonical Package Resolution     │
                                │   (Identity Mapping & Registry API)  │
                                └──────────────────┬───────────────────┘
                                                   ▼
                                ┌──────────────────────────────────────┐
                                │       10-Stage Threat Pipeline       │
                                │  OSV • NVD • EPSS • KEV • ATT&CK • PoC│
                                └──────────────────┬───────────────────┘
                                                   ▼
                                ┌──────────────────────────────────────┐
                                │   Risk Heat Scoring (0 - 100)        │
                                │   & Safe Upgrade Remediation Engine  │
                                └──────────────────┬───────────────────┘
                                                   ▼
                                ┌──────────────────────────────────────┐
                                │     History, SQLite & Exporters      │
                                │   HTML • SARIF • CycloneDX • JSON    │
                                └──────────────────────────────────────┘
```

---

## 2. Core Subsystems

### 1. Discovery & Ecosystem Layer (`pulse.ecosystems`)
- Discovers installed packages and project manifests across 14+ package ecosystems: Python (pip), Node.js (npm), Rust (Cargo), Go (Go Modules), Ruby (RubyGems), PHP (Composer), Java (Maven), .NET (NuGet), Dart (Pub), Elixir (Hex), C/C++ (Conan), Swift (SwiftPM), GitHub Actions, and Docker/Containers.
- Standardized plugin interface (`EcosystemPlugin`) with dependency topological sorting.

### 2. Declarative Web Intelligence Engine (`pulse.website`)
- Evaluates 3,000+ technology signatures across 22 domain packs.
- Pre-filtered `SignatureIndex` ensures evaluation completes in under 15 ms.
- Favicon MurmurHash3 (MMH3) fingerprinting for infrastructure recognition.
- Evaluates HTTP security headers (HSTS, CSP, X-Frame-Options, etc.).
- Resolves detected technologies into canonical `PackageInfo` models.

### 3. Vulnerability Intelligence Pipeline (`pulse.vulnerability`)
- **OSV Provider:** Batched queries to Google OSV database for package-specific advisory records and commit ranges.
- **NVD Provider:** Queries NIST NVD 2.0 API with CPE 2.3 criteria to retrieve CVSS v3.1 / v2 base scores, vector strings, and CWE weaknesses.
- **EPSS Provider:** FIRST.org Exploit Prediction Scoring System (30-day weaponization probability).
- **CISA KEV Catalog:** Local high-speed lookup against known actively exploited vulnerabilities.
- **MITRE ATT&CK Mapping:** Maps CWE weaknesses to adversarial tactics and techniques.
- **Exploit Intelligence:** Detects proof-of-concept availability and weaponization maturity.

### 4. Scoring & Attack Path Analysis (`pulse.scoring`, `pulse.attack_path`)
- **Risk Heat Score (0–100):** Weighted risk formula reflecting actual threat probability.
- **Attack Surface Score:** Normalized risk aggregate across an entire scan target.
- **Attack Path Synthesis:** Automatically correlates vulnerability chains and exposure vectors.

### 5. Verified Safe Upgrade Engine (`pulse.vulnerability.version_intelligence`)
- Compares installed versions against advisory boundaries.
- Recommends minimum safe non-vulnerable versions to minimize breaking changes.
- Analyzes breaking change risk (*Low*, *Medium*, *High*) using SemVer deltas.
- Verifies upgrade candidate safety against vulnerability databases before suggesting.

### 6. History & Reporting (`pulse.history`, `pulse.reporting`)
- SQLite-backed history tracking scans, posture deltas (new vs remediated CVEs), and report artifacts.
- Multi-format exporters: Interactive HTML Dashboard, SARIF 2.1.0, CycloneDX 1.4 SBOM, JSON Schema 2.0, and Markdown.\n