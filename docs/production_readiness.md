# Production Readiness & Functional Specification Document

This document summarizes the final production-ready state of the CVE Scanner CLI. The application has transitioned from a feature-prototype into a stable, verifiable security intelligence platform. It serves as both an architecture overview and a detailed Functional Specification (PRD) for all core capabilities.

---

## 1. Functional Specification Breakdown

### 1.1 Local Package Vulnerability Discovery
**Description**: The platform interrogates the local environment or manifest files to build an accurate software inventory before querying upstream intelligence.
**Capabilities**:
- **Environment Scanning**: Scans global and local Python (`pip`) and Node.js (`npm`) environments.
- **Manifest Parsing**: Reads and parses explicit dependency manifests including `requirements.txt`, `package.json`, and `package-lock.json`.
- **Auto-Discovery**: Recursively traverses target directories to automatically locate and scan all supported manifest files in a single execution.

### 1.2 Threat Intelligence Correlation
**Description**: Fetches, normalizes, and correlates vulnerability intelligence from multiple upstream sources to construct a unified threat profile.
**Capabilities**:
- **OSV (Open Source Vulnerability) Engine**: Queries the OSV API for ecosystem-specific vulnerability matching, capturing precise fix versions and aliases.
- **NVD (National Vulnerability Database) Enrichment**: Enriches discovered CVEs with standardized CVSS severity scores, base vectors, and detailed vulnerability descriptions.
- **Data Guardrails**: Implements strict edge validation to discard rejected, reserved, testing, or malformed CVEs before they enter the processing pipeline.

### 1.3 Exploitability & Threat Modeling
**Description**: Layers real-world exploitability context over theoretical vulnerability data to combat alert fatigue and prioritize patching.
**Capabilities**:
- **EPSS (Exploit Prediction Scoring System)**: Ingests the latest EPSS data to assign a probability score (0-100%) indicating the mathematical likelihood a CVE will be exploited in the wild within 30 days.
- **CISA KEV (Known Exploited Vulnerabilities)**: Cross-references findings against the KEV catalog to explicitly flag vulnerabilities definitively known to be used in active cyberattacks.
- **Risk Heat Score**: A proprietary prioritization algorithm that dynamically scales the threat level by mathematically weighting CVSS severity, EPSS probability, and KEV presence.

### 1.4 Attack Surface & Dependency Analysis
**Description**: Analyzes the structural relationships of vulnerabilities deep within the software supply chain.
**Capabilities**:
- **Dependency Trees**: Constructs hierarchical visualizations differentiating direct dependencies (installed by the user) from transitive dependencies (installed by other packages).
- **MITRE ATT&CK Mapping**: Maps CVE characteristics to specific MITRE tactics (e.g., Initial Access) and techniques (e.g., Exploit Public-Facing Application).
- **Attack Path Analysis**: Maps and visualizes the potential execution flow an attacker would take to exploit a deep transitive vulnerability from the root application surface.

### 1.5 Website Technology Fingerprinting
**Description**: Provides non-intrusive, passive reconnaissance of external web targets to complement internal package scanning.
**Capabilities**:
- **Technology Detection**: Identifies web servers, CMS platforms, frontend libraries, backend frameworks, and CDNs via HTTP header and HTML signature heuristics.
- **Version Boundary Tracking**: Employs heuristics to classify discovered package versions as `Confirmed` (exact semantic match), `Estimated` (e.g., `2.x`), or `Unknown`.
- **Security Header Assessment**: Evaluates the presence, absence, and misconfiguration of critical HTTP security headers (e.g., HSTS, Content-Security-Policy).

### 1.6 Historical Posture Tracking
**Description**: Maintains a persistent, offline historical record of security assessments to track team progress.
**Capabilities**:
- **Embedded SQLite Storage**: Safely stores historical scan states, packages, and CVE counts locally.
- **Posture Deltas**: Calculates point-in-time differences between scans (e.g., "3 new CVEs introduced, 2 remediated since last scan").
- **Attack Surface Scoring**: Tracks the overall mathematical degradation or improvement of the application's surface area across time.

### 1.7 Exporting & Reporting
**Description**: Generates offline-capable assets for compliance, CI/CD pipelines, and executive auditing.
**Capabilities**:
- **CycloneDX SBOMs**: Generates strictly validated, highly compliant CycloneDX v1.4 SBOM (Software Bill of Materials) JSON structures for supply chain compliance.
- **Offline HTML Dashboards**: Creates entirely self-contained, responsive, and interactive visual dashboards that require no external network calls to render safely in constrained environments.
- **Machine-Readable Formats**: Outputs fully structured JSON, CSV, and Markdown logs for custom pipeline parsing and ticketing systems.

---

## 2. Architecture & Data Integrity

The system operates via a modular pipeline architecture encompassing discovery, intelligence, correlation, tracking, and reporting. 

### Data Flow & Validation Guarantees
Data integrity is strictly enforced at the operational edge:
- **CVE Source Verification**: Discards reserved, rejected, malformed, or testing CVEs upstream before database ingestion.
- **Cache Health Validation**: Local SQLite cache operations gracefully purge malformed or corrupt JSON blobs automatically. Expired items are strictly rejected and re-fetched.
- **Schema Validation**: Vulnerability attributes enforce correct mathematical bounds for CVSS (0.0 to 10.0) and EPSS (0 to 1.0) internally.

### Export Pipeline Safety
All generated export assets comply with deterministic validation rules invoked immediately prior to file generation:
- **CycloneDX 1.4**: Must contain valid `bomFormat`, `specVersion`, `components`, `vulnerabilities`, and `dependencies` arrays.
- **JSON Pipeline**: Must retain rigorous dictionary mapping for summary metadata.
- **Offline Integrity**: The HTML generator guarantees interactive dependency tree UI components and attack path mapping logic are embedded as vanilla CSS/JS without remote CDNs.

The scanner guarantees completely localized operations where applicable, falling back gracefully to embedded cache intelligence without failing open during upstream network outages.
