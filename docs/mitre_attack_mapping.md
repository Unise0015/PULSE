# MITRE ATT&CK Threat Mapping

The CVE Scanner provides automatic translation of vulnerabilities (via CWEs) directly into **MITRE ATT&CK** techniques. This bridges the gap between software vulnerability management and threat intelligence, allowing security analysts to understand *how* a specific vulnerability could be exploited in the wild.

## Architecture

The Threat Mapping module uses a local, lightweight static dataset (`src/cve_scanner/data/cwe_attack_mapping.json`). By avoiding an external API call, the scanner maintains high performance and offline capability. 

The flow is as follows:
1. `NVDProvider` pulls the primary `CWE-ID` for the CVE.
2. `ThreatMapper` intercepts the finding in the pipeline.
3. The CWE is looked up in the JSON dataset.
4. Corresponding `AttackTechnique` models are attached to the finding.

## Current Covered CWEs

For the initial release, the following critical and common CWEs are mapped:
* **CWE-79** (Cross-site Scripting)
* **CWE-89** (SQL Injection)
* **CWE-22** (Path Traversal)
* **CWE-78** (OS Command Injection)
* **CWE-94** (Code Injection)
* **CWE-287** (Authentication Bypass)
* **CWE-434** (Unrestricted File Upload)
* **CWE-502** (Deserialization)
* **CWE-352** (CSRF)
* **CWE-918** (SSRF)

## Extending the Mapping

To add new techniques or map new CWEs, simply update `src/cve_scanner/data/cwe_attack_mapping.json`.

```json
{
  "CWE-XXX": [
    {
      "technique_id": "TXXXX",
      "technique_name": "Technique Name",
      "tactic": "Tactic Name",
      "confidence": "High"
    }
  ]
}
```

The application will automatically load the new mappings on the next scan.
