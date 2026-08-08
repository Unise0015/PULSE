# CycloneDX SBOM Export

The CVE Scanner provides native support for generating Software Bill of Materials (SBOM) using the industry-standard **CycloneDX v1.4 JSON format**.

This export capability is specifically designed to provide a threat-enriched inventory. It maps discovered packages to valid Package URLs (PURLs) and integrates directly with the scanner’s vulnerability intelligence pipeline.

## Threat Context & Security Enrichment

Unlike a standard dependency scanner that only lists components, the CVE Scanner enriches the CycloneDX SBOM with advanced cybersecurity metrics directly inside the JSON:

### Component Enrichment
For every vulnerable component, the following custom `properties` are appended:
- `cve_scanner.attack_techniques`: The MITRE ATT&CK technique IDs (e.g., `T1190,T1059`).
- `cve_scanner.attack_tactics`: The MITRE tactics (e.g., `Initial Access,Execution`).
- `cve_scanner.kev_match`: A boolean string (`true`) indicating if the component has a vulnerability currently listed in the CISA Known Exploited Vulnerabilities catalog.

### Native Vulnerabilities Array
The exporter utilizes the CycloneDX `vulnerabilities` array to document risks associated with the components:
- Native CVSS scores, severities, and vector tracking.
- Native CWE mapping (e.g., `[89]`).
- Custom `properties` for EPSS score (`cve_scanner.epss_score`) and proprietary risk heat score (`cve_scanner.risk_heat_score`).

## How to Export

1. Run a scan against your environment or a specific manifest file.
2. Once the scan completes and the post-scan menu is presented, select **Export Report**.
3. Choose **Export SBOM (CycloneDX)** from the format list.
4. The scanner will generate a fully compliant SBOM and save it to:
   `artifacts/sbom.json`

## Integration

The generated `sbom.json` can be directly ingested into:
- **Dependency-Track** for continuous SBOM analysis.
- **DefectDojo** for vulnerability management.
- Custom DevSecOps pipelines for policy enforcement based on the embedded threat properties (like KEV matches or specific ATT&CK techniques).
