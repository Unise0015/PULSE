# Website Technology Fingerprinting & Vulnerability Correlation

PULSE includes a high-performance **Declarative Web Technology Intelligence Engine** capable of detecting over **3,000+ web frameworks, CMS platforms, web servers, JavaScript libraries, CDNs, and security controls**.

---

## 1. Multi-Signal Detection Engine

PULSE evaluates target websites using multiple concurrent signal sources:

- **HTTP Response Headers:** Server banners, `X-Powered-By`, `Set-Cookie` tokens, security headers (HSTS, CSP, X-Frame-Options).
- **DOM & HTML Signatures:** Meta tags, script source URLs, link stylesheets, inline JavaScript variables, and DOM structure.
- **Script Signatures:** Asset filenames, CDN script URLs, and regex version capture groups.
- **Favicon Hash Matching:** MurmurHash3 (MMH3) hash calculation of `/favicon.ico` for rapid infrastructure and framework identification.
- **22 Domain Packs:** Signatures partitioned across Web Servers, CMS, Frontend, Backend, Databases, Cloud, CI/CD, SIEM, Firewalls, etc.

---

## 2. Canonical Vulnerability Correlation Parity

To prevent inconsistencies between standalone package scans and website technology scans, PULSE maps detected web technologies to canonical **PackageIdentities**:

```
Website Detected Technology (e.g. jQuery 1.7.2)
                     │
                     ▼
       Canonical Identity Resolution (npm:jquery)
                     │
                     ▼
          Shared Enrichment Pipeline
         (OSV • NVD • EPSS • KEV • ATT&CK)
                     │
                     ▼
        Identical Vulnerability Findings
```

### Correlation Security States:
1. **VULNERABLE:** Canonical package correlated; known security advisories found.
2. **CLEAN:** Canonical package correlated; 0 known vulnerabilities.
3. **VERSION_REQUIRED:** Technology identified, but version could not be confirmed.
4. **DETECTION_ONLY:** Non-software infrastructure or non-correlatable signal.
5. **CORRELATION_UNAVAILABLE:** Intelligence provider unreachable or ecosystem not supported.\n