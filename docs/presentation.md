# Presentation Guide

This document contains key talking points and slide content for the final project presentation.

## Core Value Proposition

"A cross-platform, developer-first command-line security intelligence tool that gives developers fast, local, automated visibility into the vulnerability posture of their installed packages using multi-source threat intelligence."

## Final Comparison Slide

```text
Traditional Scanner
-------------------
Detects vulnerabilities

CVE Scanner CLI
---------------
Detects vulnerabilities
Uses OSV intelligence
Uses NVD enrichment
Uses EPSS exploit prediction
Uses CISA KEV intelligence
Calculates Risk Heat Score
Tracks Attack Surface Score
Tracks historical posture changes
Generates interactive HTML security dashboard
```

## Key Talking Points

1. **The Problem with CVSS**: Traditional scanners rely purely on CVSS, leading to alert fatigue. We solved this by bringing in EPSS and CISA KEV to answer: *"Which vulnerability is actually being exploited right now?"*
2. **The Risk Heat Score**: Explain how the math heavily penalizes KEV presence and high EPSS probability, bubbling the true threats to the top of the list.
3. **Posture Tracking**: We aren't just a point-in-time scanner. The embedded SQLite database tracks the Attack Surface Score across time, instantly showing developers exactly what they introduced and what they fixed since their last scan.
4. **Resilience**: The scanner degrades gracefully. If NVD is down or rate-limited, the scan completes using local cache and available OSV/EPSS data, rather than crashing.
5. **No-Dependency Reporting**: We generate a beautiful, responsive, offline-capable HTML dashboard with embedded CSS and vanilla JS, meaning reports can be emailed or opened safely in constrained environments.
