# Vulnerability Intelligence & Threat Enrichment

This document provides the raw technical implementation details for the dual-engine enrichment pipeline inside `pulse.services.enrichment_pipeline.EnrichmentPipeline`.

---

## 1. The OSV (Open Source Vulnerabilities) Pipeline (`pulse.enrichment.osv_provider.OSVProvider`)

### Query Construction & Batching
OSV enforces strict REST API rate limits. Instead of individual queries, PULSE utilizes the `https://api.osv.dev/v1/querybatch` endpoint.
- **Batch Chunking Algorithm:** Packages are chunked into lists of 1000 items (`itertools.batched(packages, 1000)`).
- **Canonical Ecosystem Mapping:** Internal PULSE ecosystem enums are strictly mapped to OSV strings (e.g., `Ecosystem.PYTHON -> "PyPI"`, `Ecosystem.NODE -> "npm"`).
- **Asynchronous I/O:** Batches are fired concurrently using `asyncio.gather` with `httpx.AsyncClient`.

### Version Matching
The OSV API natively understands semver constraints and resolves `PackageInfo.version` against the vulnerability `affected` block. If `version` is absent, the API returns all vulnerabilities for the package, which PULSE will deduplicate based on highest severity.

---

## 2. The NVD & CPE Pipeline (`pulse.enrichment.nvd.correlator.NVDCorrelationEngine`)

### Candidate Resolution (`pulse.correlation.cpe.resolvers.CPEResolver`)
System binaries and web infrastructure do not have standard package names. 
- The resolver attempts to yield multiple `CPECandidate` objects based on vendor permutations (e.g., `nginx` -> `cpe:2.3:a:f5:nginx`, `cpe:2.3:a:nginx:nginx`).
- Fallback candidates are sorted by a deterministic heuristic confidence score.

### API Caching (`pulse.enrichment.nvd.cache.NVDCorrelationCache`)
NVD is highly rate-limited (5 requests / 30s without key).
- An SQLite DB at `~/.pulse/cache/nvd.db` stores raw CVE arrays keyed by the CPE prefix.
- The cache adheres to a strict 24-hour TTL (`cache_ttl_hours=24`) before attempting a network re-fetch.

### Local Version Evaluation (`NVDVersionMatcher`)
Unlike OSV, NVD API returns ALL vulnerabilities for a CPE string if the version is not perfectly formatted.
- The `NVDVersionMatcher` runs locally.
- It iterates through the CVE's `configurations.nodes.cpeMatch` arrays.
- It performs semantic comparison using the `packaging.version` library against `versionStartIncluding`, `versionStartExcluding`, `versionEndIncluding`, and `versionEndExcluding`.
