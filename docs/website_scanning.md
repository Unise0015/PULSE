# Website assessment

PULSE first observes a website, then lets you explicitly correlate detected technologies with vulnerability intelligence. Detection alone does not establish that a website is secure.

## Acquisition and detection

`WebsiteFingerprintAnalyzer` makes synchronous HTTPX requests with timeouts, bounded decoded bodies, and a redirect limit. It analyzes response headers, cookies, HTML and script URLs with built-in and declarative signatures. It also requests a favicon, a generated error-page path, and robots.txt for additional evidence. It does not execute JavaScript or crawl an entire site. Auxiliary requests follow the final page URL after redirects. URL validation runs before every request, including redirects. External-only mode rejects localhost names and non-public DNS answers and connects to a checked address while retaining the original Host and TLS server name. It bypasses environment proxies to prevent proxy-side DNS from bypassing these checks. The bounded transport negotiates gzip/deflate and limits output inside decompression; unsupported encodings fail explicitly.

The root page state is `OK`, `PARTIAL`, `ERROR`, `INVALID`, or `OFFLINE`. HTTP errors, a reached root download limit, and signature failures produce coverage warnings. Optional resource probes are best effort; unavailable optional resources do not establish absence of a technology. Offline mode performs no acquisition.

## Reading results

The summary separates website access, detected technologies, recorded vulnerability results, and correlation state. The technology inventory uses recorded results only; opening a view or exporting does not trigger package resolution or provider calls.

- **Not checked:** No per-technology vulnerability check was recorded, including older history without those details.
- **Version required:** Confirm the deployed version before correlation.
- **Detection only:** The technology provides context but cannot be correlated.
- **Check incomplete:** Lookup failed or finding details are unavailable; zero findings is inconclusive.
- **No known vulnerabilities:** A recorded check returned no known matches. This is not a security guarantee.
- **Vulnerabilities found:** Review the recorded findings and remediation.

Correlation resolves canonical package identities and runs the shared enrichment pipeline. Partial or failed attempts offer a retry. Invalid, offline, failed acquisition, and empty inventories do not offer correlation. Unexpected correlation failures return a failed assessment with recovery guidance.

Security headers show observed values, missing-header guidance, and basic validation for X-Frame-Options, X-Content-Type-Options and HSTS. These checks are not a complete policy audit; review CSP and cross-origin policies in application context.

## Exports and history

Export Report in the website menu exports the current assessment. HTML includes acquisition status, technology check details, and security headers; text, Markdown and JSON preserve the same website view data. Tables can scroll independently on small screens. New history preserves the final URL, header evidence, per-technology check results, and finding associations. Successful retries replace earlier correlation warnings while retaining acquisition warnings. Legacy history may lack per-technology results or header evidence, which is displayed as unavailable rather than clean.
