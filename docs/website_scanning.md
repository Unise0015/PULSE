# Website Scanning Engine Specifications

The Web Technology Intelligence Engine relies on declarative evaluation and AST-style DOM parsing to identify capabilities.

---

## 1. Multi-Vector Fingerprinting (`pulse.website.website_fingerprint.WebsiteFingerprintAnalyzer`)
The analyzer fires concurrent `httpx.AsyncClient` requests to extract signals.

- **HTTP Analysis (`_analyze_headers`)**: Reads `response.headers`. Regex runs against `Server` and `X-Powered-By`.
- **DOM Parsing (`_analyze_dom_and_scripts`)**: Uses `BeautifulSoup4`. 
  - Searches `<meta name="generator">` for explicit CMS tags (e.g., WordPress).
  - Searches `<script src="">` to match known CDN URLs for libraries (e.g., React, jQuery).
- **Favicon Algorithm (`FaviconHasher`)**: 
  - Fetches `/favicon.ico`.
  - Base64 encodes the byte stream.
  - Runs a MurmurHash3 (`mmh3.hash()`) integer conversion.
  - Performs an O(1) dictionary lookup against `pulse/website/favicon_hashes.json`.

---

## 2. Declarative Signature Matcher (`pulse.website.declarative_engine.DeclarativeEngine`)
The engine iterates `pulse.website.technology_catalog.TECHNOLOGY_CATALOG`.

### Signature Data Structure
Each technology entry requires:
- `implies`: Sub-technologies (e.g., "Laravel" implies "PHP").
- `regex_rules`: Array of PCRE regex strings mapped to headers/DOM/scripts.
- `version_group`: The regex capture group `` that extracts the exact version string (e.g., `^React/([0-9\.]+)`).

### Output Object (`TechnologyFingerprint`)
When matched, a fingerprint is yielded with `confidence_score` (1-100) and `version_extracted` (str | None).

---

## 3. Capability Transition (`pulse.website.capability`)
A `TechnologyFingerprint` must transition into a vulnerability query entity.
- **`CORRELATABLE`**: Passes `ecosystem` mapping (e.g., npm) straight to `OSVProvider`.
- **`DETECTION_ONLY`**: Halts processing (e.g., Cloudflare CDN).
- **`VERSION_REQUIRED`**: Halts processing if `version_extracted` is None, explicitly avoiding NVD false-positive spam.
