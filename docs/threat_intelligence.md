# Threat Intelligence Sources

CVE Scanner CLI relies on a carefully orchestrated pipeline of four distinct threat intelligence sources.

## 1. OSV (Open Source Vulnerability) Database
- **Role:** The primary discovery and matching engine.
- **Why we use it:** Traditional scanners attempt to match packages to CVEs using CPEs (Common Platform Enumerations), which is notoriously inaccurate for open-source packages (like npm and PyPI). OSV maps vulnerabilities directly to specific open-source package names and versions.
- **Integration:** Batched API calls to `api.osv.dev`. Responses provide the baseline CVE ID and description.

## 2. NVD (National Vulnerability Database)
- **Role:** CVSS Score Enrichment.
- **Why we use it:** While OSV knows *if* a package is vulnerable, it does not always contain the authoritative CVSS metrics. We use the NVD API v2 to retrieve the official CVSS v3.1/v2 base scores and severities.
- **Integration:** API calls to `services.nvd.nist.gov`. Due to aggressive NIST rate limits, results are heavily cached locally in SQLite.

## 3. EPSS (Exploit Prediction Scoring System)
- **Role:** Threat Forecasting.
- **Why we use it:** Managed by FIRST (Forum of Incident Response and Security Teams), EPSS uses machine learning on real-world threat feeds to predict the probability of a CVE being exploited in the next 30 days.
- **Integration:** Batched queries (up to 100 CVEs at a time) to `api.first.org`.

## 4. CISA KEV (Known Exploited Vulnerabilities)
- **Role:** Ground Truth Evidence.
- **Why we use it:** The U.S. government maintains this catalog of vulnerabilities that have been definitively observed in active cyberattacks. Any match here is a critical, drop-everything priority.
- **Integration:** The entire JSON catalog is downloaded from `cisa.gov` and cached locally for rapid O(1) dictionary matching during the scan.

## The Enrichment Pipeline

When a vulnerable package is found, it moves through the pipeline sequentially:

1. **OSV** says: "Package X version Y has CVE-Z."
2. **NVD** says: "CVE-Z has a CVSS of 8.1 (High)."
3. **EPSS** says: "CVE-Z has a 94% chance of being exploited this month."
4. **KEV** says: "CVE-Z has been actively exploited since May 1st."
5. **Scanner** calculates: "This is a priority 1 fix with a Risk Heat Score of 95."
