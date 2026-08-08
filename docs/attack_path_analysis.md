# Attack Path Analysis

The CVE Scanner now includes native **Attack Path Analysis**, mapping out the potential path an attacker could take to exploit discovered vulnerabilities. This elevates the scanner from providing a simple vulnerability inventory to offering actionable threat prioritization based on exposure scoring.

## Methodology

The Attack Path Analysis engine processes vulnerabilities and constructs paths using existing platform intelligence. The path follows the structure:
`Package ↓ CVE ↓ CWE ↓ MITRE ATT&CK Technique`

### Exposure Scoring (Deterministic)

Each attack path receives an **Exposure Score** (max 95), designed to strictly prioritize findings based on real-world exploitability indicators rather than raw theoretical severity.

The model uses the following weights:

*   **KEV Match (+40)**: Highest weight. If CISA confirms active exploitation in the wild, the exposure is critical.
*   **EPSS > 50% (+25)**: If the exploit prediction score is above 50%, there is a high probability of near-term exploitation.
*   **CVSS Severity (Exclusive)**:
    *   **CVSS ≥ 9 (+20)**: Critical base severity.
    *   **CVSS ≥ 7 (+10)**: High base severity.
*   **MITRE Mapping (+10)**: If the finding can be mapped to an actionable MITRE ATT&CK technique, the path is structurally defined.

By using *exclusive* scoring for CVSS, the platform ensures that raw severity metrics do not drown out more actionable indicators like KEV or EPSS.

## Example Path

```text
Package: Django 3.2.0

Path:
CVE-2022-34265
↓
CWE-89
↓
T1190 Exploit Public-Facing Application

Exposure Score: 95
```

## JSON Export

Users can export the prioritized attack paths directly into a structured JSON file via the post-scan **Export Report** menu (`Export Attack Paths (JSON)`). This export encapsulates all path elements, including extracted MITRE tactics, enabling future integrations.

## Roadmap: M7.4+ Dependency Tree Expansion

Currently, the Attack Path Analyzer focuses on package-level mapping. The planned M7.4 milestone will introduce full dependency graph resolution, expanding the path to include:
`Root Project ↓ Transitive Dependency ↓ CVE ↓ CWE ↓ ATT&CK Technique`
