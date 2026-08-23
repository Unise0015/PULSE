# System Architecture Blueprint

PULSE is a highly decoupled, state-driven vulnerability intelligence engine. This document serves as the absolute technical reference for its architectural execution.

---

## 1. Core Data Models (`pulse.domain.models`)
All inter-layer communication uses strictly typed Python Dataclasses.

- **`PackageInfo`**: The canonical representation of a discovered dependency.
  - Fields: `name` (str), `version` (str), `ecosystem` (enum), `source_file` (str).
- **`VulnerabilityFinding`**: The unified threat object returned from intel pipelines.
  - Fields: `cve_id`, `cvss_score`, `epss_score`, `kev_match`, `risk_heat_score`, `attack_techniques`.
- **`ScanResult`**: The final output container.
  - Fields: `target_name`, `timestamp`, `findings` (List[VulnerabilityFinding]), `attack_paths` (List[AttackPath]).

---

## 2. Global State Management (`pulse.state.AppState`)
PULSE maintains a singleton state module to control execution flags globally without prop-drilling.
- `AppState.SYSTEM_SCAN` (bool): If True, instructs the orchestrator to prioritize OS/Kernel discovery.
- `AppState.OFFLINE_MODE` (bool): Hard-blocks any network requests in `OSVProvider` and `NVDCPEProvider`, forcing cache-only reads.
- `AppState.LAST_SCAN`: Stores the final `ScanResult` object for immediate memory access by the Reporting Engine.

---

## 3. The Execution Flow (`pulse.scanner.ScannerOrchestrator`)
The `ScannerOrchestrator` controls the sequence of a scan. The exact call stack for a file scan:

1. **Discovery Request**: `orchestrator.run_file_scan("requirements.txt")`
2. **Parsing Routing**: `ParserRegistry.get_parser_for_file()` uses regex against the filename to load `parse_requirements_txt()`.
3. **AST Translation**: The parser yields raw text blocks into `PackageInfo` models.
4. **Enrichment Hook**: `EnrichmentPipeline.run_pipeline(packages)` is invoked.
5. **Data Deduplication**: The pipeline hashes `(name, version, ecosystem)` to drop duplicate packages.
6. **Threat Scoring**: The `ThreatMapper` injects CVSS and KEV data to calculate the `risk_heat_score`.
7. **Finalization**: `ReportBuilder` serializes the `ScanResult` into JSON/HTML.
