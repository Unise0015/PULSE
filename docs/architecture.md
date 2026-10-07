# Scan architecture

## Entry points and orchestration

`pulse.cli` collects input and calls `ScannerOrchestrator`. The orchestrator delegates project discovery to `ScanService`, selected packages to `PackageService`, and website assessment to `WebsiteService`. File parsing feeds selected packages into `run_targeted_scan`.

`EnrichmentPipeline.run` executes registry, vulnerability, scoring, and recommendation stages. Its result carries findings, attack paths, packages, metrics, and warnings. Failed stages preserve prior findings and add a warning. Intelligence lookup failures must remain distinct from successful empty results; failed OSV batches are never stored as clean cache entries.

## Completion evidence

`ScanResult.warnings` carries execution warnings. `ScanResult.assessment_warnings` combines them with discovery diagnostics, skipped packages, and website correlation state. Terminal summaries, report construction, and history all consume this evidence.

An incomplete scan can still contain useful findings. Its empty result cannot establish a clean assessment, its score is partial, and it cannot establish remediation against a previous scan. History stores warnings in `scan_runs.warnings_json` and website completion state in `website_state_json`; older records with no coverage evidence are displayed as unknown rather than verified.

Website correlation also retains `Partial` and `Failed` states. An eligible technology with incomplete checks is not labelled as having no known vulnerabilities.

## Website observations and package identity

`website.acquisition.fetch_observation` owns bounded, streamed HTTP reads for the root document, favicon, error probe, and robots.txt. It preserves case-insensitive headers and closes responses at the byte limit. Failed root requests return explicit assessment diagnostics.

The signature registry and declarative rules detect technologies from those observations. AngularJS (`angular` on npm) and modern Angular (`@angular/core`) remain distinct throughout detection, deduplication, and correlation.

`ecosystems.package_identity` owns canonical package aliases. A technology display name can have a different meaning from a literal registry package name: the detected technology `Angular` denotes modern Angular; the literal npm package `angular` denotes AngularJS.

## Reports and storage

`ReportBuilder` converts a `ScanResult` into a shared report model for JSON, HTML, Markdown, and text. Reports carry completion evidence alongside findings. HTML rendering escapes untrusted values and accepts only HTTP(S) finding links. Templates and signature data are packaged with the distribution.

`HistoryService` uses SQLite for scan metadata, findings, and inventories. `ReportService` records scans and optionally writes reports using the configured format and location.

## Verification

See [testing.md](testing.md) for the tracked regression suite and CI checks. Tests use synthetic provider responses and isolated history databases.
