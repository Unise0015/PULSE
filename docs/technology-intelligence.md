# PULSE Universal Technology Intelligence Architecture

PULSE's **Universal Technology Intelligence Platform** unifies dependency scanning, web application fingerprinting, and infrastructure technology detection into a single model and vulnerability intelligence pipeline.

---

## 1. Unified Technology Model (`TechnologyFingerprint`)

Every detected technology—whether a Python dependency, a web framework, or a network firewall—is represented by a unified model:

- **`name`**: Technology name (e.g. `Nginx`, `WordPress`, `Django`)
- **`vendor`**: Vendor or organizational owner (e.g. `F5`, `WordPress`, `Django Software Foundation`)
- **`version`**: Extracted semantic version or `None` if version cannot be determined from empirical evidence
- **`category`**: Functional taxonomy (e.g. `Web Server`, `CMS`, `Firewall`)
- **`domain`**: Functional domain (`web`, `cms`, `frontend`, `backend`, `database`, `messaging`, `api_gateway`, `cloud`, `cdn_waf`, `network`, `firewall`, `vpn`, `virtualization`, `storage`, `containers`, `service_mesh`, `devops`, `monitoring`, `siem`, `identity`, `enterprise`, `embedded`)
- **`confidence`**: Deterministic score (0–100)
- **`direct_detection`**: `True` if directly observed; `False` if inferred from a parent technology
- **`inferred`**: `True` if derived via technology implication graphs
- **`vulnerability_status`**:
  - `EXACT`: Both technology identity and version are confirmed with mapped CPE
  - `PARTIAL`: Technology identity confirmed with CPE, but exact version is unknown
  - `UNRESOLVED`: CPE mapping unavailable for this technology

---

## 2. Multi-Domain Signature Architecture (`data/technology_signatures/`)

Technology definitions are modularized into 22 domain signature packs under `src/pulse/data/technology_signatures/`. Adding a new technology requires adding JSON metadata rather than writing custom Python code.

---

## 3. Dynamic Discovery & Performance Indexing

The `SignatureLoader` dynamically discovers signature packs across directories. Rules are indexed by header keys, cookie names, and meta tag keys (`SignatureIndex`), maintaining evaluation time **under 15 ms** per target response.
