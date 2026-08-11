# Website Technology Fingerprinting & Intelligence

PULSE features a production-ready, high-performance **Declarative Web Technology Intelligence Engine** capable of detecting over **3,000+ web frameworks, CMS platforms, web servers, JavaScript libraries, CDNs, and security controls**.

---

## Architecture Overview

The web technology subsystem combines two complementary signature systems:

1. **Declarative Engine (`src/pulse/website/declarative/`)**:
   - Parses declarative JSON signatures (`pulse/data/web_signatures/`).
   - Uses zero-cost pre-filtered lookup indexes (`SignatureIndex`) for headers, cookies, meta tags, script URLs, and HTML body patterns.
   - Extracts semantic versions via capture groups (`version:\1`).
   - Resolves technology implication graphs recursively (`Next.js` -> `React` -> `Node.js`).
   - Maps embedded CPE strings directly to NVD vulnerability correlation datasets.

2. **Python Signatures (`src/pulse/website/signatures/`)**:
   - Backward-compatible Python signature classes (`SignatureRegistry`) providing custom matchers for specific complex scenarios.

3. **Favicon Fingerprinter (`src/pulse/website/favicon_fingerprint.py`)**:
   - MD5 hash matching against `/favicon.ico` byte streams for 100% accurate identification of routers, servers, and web applications.

---

## Detection Evidence & Explainability

Every detected technology retains its underlying match evidence:

- **Source**: `header`, `cookie`, `html`, `script`, `meta`
- **Matched Value**: Exact snippet or string matched
- **Pattern**: Signature regular expression or string pattern
- **Confidence**: Deterministic 0–100 confidence score
- **Inferred Status**: Distinguishes direct detections from implied dependencies (`inferred=True`, `inferred_from="Next.js"`)

---

## Safety & Performance Controls

- **Passive Default**: Website scanning is 100% passive by default (single HTTP GET stream).
- **Body Truncation Protection**: Limits HTML body evaluation to a configurable `MAX_BODY_SIZE` (default 2 MB) to prevent unbounded regex processing.
- **Pre-Filtering Index**: Header, cookie, and meta rules are indexed by name. Only rules matching response keys present in the target response are evaluated, keeping signature evaluation P95 < 100 ms.
- **Error Classification**: Distinguishes between `SUCCESS`, `NETWORK_ERROR`, and `NOT_FOUND` without misclassifying connection timeouts as missing technologies.

---

## Vulnerability Pipeline Integration

Once technologies are detected and resolved to CPEs (e.g. `cpe:2.3:a:wordpress:wordpress:6.5:*:*:*:*:*:*:*`), PULSE feeds them into the core vulnerability pipeline:

```
Technology Fingerprint -> CPE Candidate -> NVD / OSV Provider -> EPSS / KEV / ATT&CK Enrichment -> Risk Heat Score -> Report Exporters
```
