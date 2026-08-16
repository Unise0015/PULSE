# Threat Intelligence & Enrichment Pipeline

PULSE integrates a multi-source threat intelligence pipeline to provide contextual, actionable vulnerability data rather than static CVSS scores alone.

---

## 1. Intelligence Sources

| Source | Role | Update Mechanism | Impact on Prioritization |
| :--- | :--- | :--- | :--- |
| **OSV Database** | Package-specific vulnerability detection | Live REST API (`api.osv.dev`) + SQLite Cache | Primary matching engine; determines affected version ranges. |
| **NVD (NIST)** | Authoritative CVSS metrics & CWE classification | NIST NVD 2.0 API + SQLite Cache | Provides CVSS v3.1 Base Score, Severity, and CWE identifiers. |
| **EPSS (FIRST.org)** | 30-day exploit prediction probability | FIRST EPSS API (`api.first.org`) | Quantifies likelihood of weaponization in the next 30 days. |
| **CISA KEV** | Active in-the-wild exploitation catalog | CISA JSON Catalog + Local Cache | Confirmed active cyberattacks; applies a high-priority multiplier. |
| **MITRE ATT&CK** | Adversarial TTP mapping | Internal ATT&CK Enterprise Matrix | Identifies attacker tactics (e.g. Initial Access, Privilege Escalation). |
| **Exploit Intel** | Public PoC & weaponization tracking | Exploit Intelligence Engine | Classifies exploit maturity (*Active*, *Weaponized*, *Functional*, *PoC*). |

---

## 2. The 10-Stage Pipeline Lifecycle

When software dependencies or web technologies are scanned, each candidate moves sequentially through the enrichment pipeline:

```
[Package/Technology]
       │
       ▼
 1. Version Intelligence ──────► Parse SemVer & normalizes release format
       │
       ▼
 2. OSV Query ─────────────────► Identify matching advisory records (GHSA, PYSEC, RUSTSEC, etc.)
       │
       ▼
 3. NVD Enrichment ────────────► Retrieve CVSS v3.1 Base Score, Vector, & CWE
       │
       ▼
 4. EPSS Scoring ──────────────► Fetch FIRST.org exploit prediction probability percentile
       │
       ▼
 5. CISA KEV Lookup ───────────► Check against Known Exploited Vulnerabilities catalog
       │
       ▼
 6. MITRE ATT&CK ──────────────► Map CWE to adversarial Tactics, Techniques, & Procedures
       │
       ▼
 7. Exploit PoC Analysis ──────► Assess public exploit availability & maturity
       │
       ▼
 8. Risk Heat Calculation ─────► Compute composite Risk Heat Score (0 - 100)
       │
       ▼
 9. Attack Path Synthesis ─────► Build exposure-scored attack chains
       │
       ▼
10. Remediation Advisor ───────► Determine minimum safe target version & breaking change risk
```\n