# Product Requirements Document: CVE Scanner CLI

**Status:** Approved  
**Version:** 4.0 — Competitive Edition  
**Date:** June 2026  
**Scope:** CLI Tool Only — Interactive Banner, Multi-Source Intel, Report Export, API Key Management

---

## 1. Executive Summary

### 1.1 Overview

CVE Scanner CLI is a cross-platform, developer-first command-line security intelligence tool that gives developers and security teams fast, local, automated visibility into the vulnerability posture of their installed packages. It launches with a rich interactive terminal experience — a branded animated banner, a guided session menu, and a live scanning interface — inspired by Gemini CLI and Claude Code.

Unlike existing free scanners such as OWASP CVE Lite CLI (which focuses exclusively on JavaScript/TypeScript lockfiles and the OSV database), CVE Scanner targets **all languages and ecosystems** — Python, Node.js, and system packages — and enriches every CVE finding with **multi-source threat intelligence**: NVD API v2, EPSS exploit probability, and the CISA Known Exploited Vulnerabilities catalog. Results can be exported in five human-readable formats: **PDF, Markdown, TXT, CSV, and JSON**.

### 1.2 Problem Statement

Developers and security teams need fast, local, automated visibility into their dependency security posture. Existing tools are either too narrow (JS only), lack real-world exploit context, or produce output that requires manual triage. Specifically:

- **CVE Lite CLI (OWASP)** is excellent for JS/TS lockfile scanning but covers no other language or ecosystem, uses only the OSV database (no EPSS or KEV), and has no interactive session or persistent watch mode.
- **npm audit / pip-audit** are ecosystem-locked and produce no cross-ecosystem view.
- No free tool combines: multi-ecosystem auto-discovery + EPSS exploit probability + CISA KEV active-exploitation status + a composite Risk Heat Score + professional report exports + an interactive session UI.

CVE Scanner fills this gap.

### 1.3 Core Design Principles

- **Multi-ecosystem first** — Python, Node.js, and system packages in a single scan
- **Exploit-aware** — CVSS alone is insufficient; EPSS + KEV tell you what is being exploited *today*
- **Interactive, not scriptlike** — feels like a product (Gemini/Claude CLI model), not a one-shot command
- **Human-readable reports** — PDF and MD reports for auditors; TXT and CSV for logs and spreadsheets
- **Zero cloud, zero account** — all data stays local; API keys are optional performance upgrades

---

## 2. Competitive Differentiation

### 2.1 How We Are Different from CVE Lite CLI (OWASP)

CVE Lite CLI is a well-built, OWASP-recognized tool. We respect it. Here is where CVE Scanner goes further:

| Capability | CVE Lite CLI | CVE Scanner CLI |
|---|:---:|:---:|
| JavaScript / TypeScript scanning | ✅ | ✅ |
| Python (pip) scanning | ❌ | ✅ |
| System packages (apt, brew, rpm, winget) | ❌ | ✅ |
| Vulnerability data source | OSV only | NVD v2 + EPSS + CISA KEV |
| EPSS exploit probability score | ❌ | ✅ |
| CISA KEV active-exploitation badge | ❌ | ✅ |
| Composite Risk Heat Score (0–100) | ❌ | ✅ |
| Interactive session banner + menu | ❌ | ✅ |
| Live streaming scan progress | ❌ | ✅ |
| Watch mode (continuous background scan) | ❌ | ✅ |
| Scan history + delta diff | ❌ | ✅ |
| PDF report export | ❌ | ✅ |
| Markdown report export | ❌ | ✅ |
| TXT report export | ❌ | ✅ |
| CSV report export | ❌ | ✅ |
| JSON report export | ✅ | ✅ |
| Interactive API key manager | ❌ | ✅ |
| Slack / email alert webhooks | ❌ | ✅ |
| CI/CD exit code gating | ✅ | ✅ |
| No account required | ✅ | ✅ |
| Fully local / no telemetry | ✅ | ✅ |

### 2.2 Our Unique Angle — Three Things No Free Tool Has Together

**1. Multi-ecosystem auto-discovery in one session**  
A single `cve-scan --auto-discover` finds Python pip packages, Node.js project dependencies, and system-level packages (apt/brew/rpm/winget) all in the same scan. No other free tool does this.

**2. EPSS + KEV threat intelligence on every CVE**  
Knowing a CVE is "Critical" is not enough. EPSS tells you the probability it will be exploited in the next 30 days. CISA KEV tells you it is being exploited *right now*. Combined into a Risk Heat Score (0–100), this is meaningfully different from raw CVSS ranking.

**3. Interactive session with persistent context**  
The tool does not exit after a scan. It stays open, lets you export in multiple formats, view history, compare against last scan, and configure alerts — all in one session without re-running. This is the CLI experience of Gemini CLI and Claude Code applied to security scanning.

---

## 3. Target Audience

| Persona | Primary Need | Key Differentiator |
|---|---|---|
| Local developer | Quick scan before commit | Interactive mode, auto-discover all ecosystems |
| DevSecOps / CI engineer | Pipeline security gate | Exit codes, JSON output, non-interactive mode |
| Security auditor | Professional audit report | PDF + MD export with EPSS/KEV context |
| Team lead / manager | Posture trend tracking | Scan history, delta diff, Attack Surface Score |

---

## 4. Interactive CLI Experience

### 4.1 Launch Banner

```
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║    ██████╗██╗   ██╗███████╗    ███████╗ ██████╗ █████╗  ║
║   ██╔════╝██║   ██║██╔════╝    ██╔════╝██╔════╝██╔══██╗ ║
║   ██║     ██║   ██║█████╗      ███████╗██║     ███████║ ║
║   ██║     ╚██╗ ██╔╝██╔══╝      ╚════██║██║     ██╔══██║ ║
║   ╚██████╗ ╚████╔╝ ███████╗    ███████║╚██████╗██║  ██║ ║
║    ╚═════╝  ╚═══╝  ╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝ ║
║                                                          ║
║         Vulnerability Intelligence • v4.0               ║
║    Zero-cloud. Multi-ecosystem. Built for developers.   ║
╚══════════════════════════════════════════════════════════╝

  Version  : 4.0.0
  NVD Key  : ✓ Configured        (50 req/30s)
  EPSS     : ✓ Active
  KEV      : ✓ Cached            (updated 3h ago)
  Last Scan: June 7 2026 14:32   (492 packages · Score: 63/100)
```

- Renders with `rich` gradient coloring (red → orange)
- Animates line-by-line on first launch
- Skip with `--no-banner` flag

### 4.2 Main Menu (Session Loop)

```
  What would you like to do?

  [1]  Scan a single package
  [2]  Auto-discover & scan all packages
  [3]  Scan from file  (requirements.txt / package.json)
  [4]  Lookup a CVE ID directly
  [5]  Export last scan report
  [6]  View scan history & compare
  [7]  Manage API keys & alerts
  [8]  Settings
  [9]  Help
  [0]  Exit

  ❯ _
```

- Arrow keys + number shortcuts via `questionary`
- `Ctrl+C` returns to menu cleanly (no crash)
- `Ctrl+D` / `0` exits with goodbye message
- After every action, returns to this menu

### 4.3 Live Scan Progress

```
  ┌─ Scanning ──────────────────────────────────────────┐
  │  Discovering packages...                            │
  │  ✓ Python (pip)    142 packages                     │
  │  ✓ Node (npm)       38 packages                     │
  │  ✓ System (apt)    312 packages                     │
  │                                                     │
  │  Fetching CVE data  ━━━━━━━━━━━━━━━━━  187/492      │
  │  Enriching with EPSS + KEV...                       │
  │                                                     │
  │  🔴 requests 2.27.0  →  CVE-2023-32681 (CRITICAL)   │
  │  🟠 django 3.2.0     →  CVE-2023-36053 (HIGH)       │
  │  🔴 openssl 3.0.1    →  CVE-2022-0778  ⚠ KEV MATCH  │
  └─────────────────────────────────────────────────────┘
```

- CVE findings stream live as discovered — no waiting until the end
- KEV matches flash warning immediately
- Shows ETA based on remaining packages + rate limit

### 4.4 Post-Scan Summary

```
  ┌─ Scan Complete ─────────────────────────────────────┐
  │  Packages scanned  :  492                           │
  │  Vulnerable        :   17  |  Clean  :  475         │
  │                                                     │
  │  🔴 Critical  :  2    🟠 High    :  5               │
  │  🟡 Medium    :  8    🟢 Low     :  2               │
  │                                                     │
  │  ⚠  KEV Matches    :  1  (actively exploited!)      │
  │  📊 Attack Surface :  63/100  (+8 vs last scan)     │
  └─────────────────────────────────────────────────────┘

  What next?
  [1] View full results    [2] Export report    [3] Menu
```

### 4.5 Non-Interactive (CI/Pipe) Mode

When arguments are passed or stdout is not a TTY, no banner or menu appears:

```bash
cve-scan --file requirements.txt --severity high --output json --no-interactive
```

---

## 5. API Key Management

### 5.1 Interactive Key Manager (Menu Option 7)

```
  ┌─ API Key Management ────────────────────────────────┐
  │                                                     │
  │  [1]  NVD API Key        ✓ Configured               │
  │  [2]  EPSS API           — No key needed (free)     │
  │  [3]  CISA KEV           — No key needed (free)     │
  │  [4]  Slack Webhook      ✗ Not configured           │
  │  [5]  Discord Webhook    ✗ Not configured           │
  │  [6]  Email (SMTP)       ✗ Not configured           │
  │                                                     │
  │  [7]  View config file path                         │
  │  [8]  Reset all keys                                │
  │  [0]  Back                                          │
  └─────────────────────────────────────────────────────┘
```

### 5.2 Adding a Key (Interactive Flow)

```
  Enter your NVD API key:
  (Get a free key: https://nvd.nist.gov/developers/request-an-api-key)

  ❯ ************************************  [hidden input]

  ✓ Key saved to ~/.cve-scanner/.env
  ✓ Rate limit upgraded: 5 req/30s → 50 req/30s

  Test connection? [Y/n]: Y
  ✓ NVD API responded 200 OK
```

### 5.3 Config File — `.env` at `~/.cve-scanner/.env`

Auto-managed by the interactive key manager. User never needs to edit it manually — but can.

```env
# CVE Scanner — API Configuration
# Managed by: cve-scan key manager
# Last updated: 2026-06-07

# ── NVD API ──────────────────────────────────────────────────
# Get a free key: https://nvd.nist.gov/developers/request-an-api-key
# Without key: 5 req/30s | With key: 50 req/30s
NVD_API_KEY=

# ── Slack alerts (optional) ───────────────────────────────────
# Format: https://hooks.slack.com/services/T.../B.../...
SLACK_WEBHOOK_URL=

# ── Discord alerts (optional) ─────────────────────────────────
DISCORD_WEBHOOK_URL=

# ── Microsoft Teams alerts (optional) ────────────────────────
TEAMS_WEBHOOK_URL=

# ── Email alerts via SMTP (optional) ─────────────────────────
SMTP_HOST=
SMTP_PORT=587
SMTP_USER=
SMTP_PASSWORD=
ALERT_EMAIL_TO=

# ── Scan defaults ─────────────────────────────────────────────
DEFAULT_SEVERITY=high
DEFAULT_OUTPUT=table
DEFAULT_REPORT_DIR=~/cve-reports/
DEFAULT_REPORT_NAME=cve_report
```

### 5.4 Key Validation

| Key | Validation method |
|---|---|
| NVD | Test GET to NVD API — checks 200 OK |
| Slack | Test POST webhook — sends "CVE Scanner connected ✓" |
| Discord | Test POST webhook — same |
| SMTP | Test SMTP connection — no email sent |

### 5.5 Environment Variable Override

Shell env vars take priority over `.env` file:

```bash
export NVD_API_KEY=abc123
cve-scan --auto-discover
```

### 5.6 Non-Interactive Key Setup

```bash
cve-scan --set-key nvd YOUR_KEY_HERE
cve-scan --set-key slack https://hooks.slack.com/...
```

---

## 6. Report Export System

All five formats export from the same scan result. Use `--output` flag or the interactive export menu.

### 6.1 Interactive Export Menu

```
  ┌─ Export Report ─────────────────────────────────────┐
  │                                                     │
  │  [1]  PDF      — professional report, cover page    │
  │  [2]  Markdown — .md with tables and badges         │
  │  [3]  TXT      — plain text, no color codes         │
  │  [4]  CSV      — flat spreadsheet (Excel/Sheets)    │
  │  [5]  JSON     — machine-readable full data         │
  │  [6]  All      — export all five at once            │
  │                                                     │
  │  Output dir : ~/cve-reports/      [change]          │
  │  Report name: cve_report_2026-06-07  [change]       │
  └─────────────────────────────────────────────────────┘
```

### 6.2 PDF Report

**Library:** `reportlab`  
**Filename:** `cve_report_YYYY-MM-DD.pdf`

**Sections:**
1. Cover page — tool name, scan date, hostname, summary stats
2. Attack Surface Score gauge + severity breakdown bar chart
3. Actively Exploited (KEV) — highlighted red section
4. Critical & High findings — one card per CVE with CVSS, EPSS%, Risk Heat Score bar
5. Medium & Low — condensed table format
6. Remediation table — package → current → safe upgrade version
7. Appendix — full scanned packages list

### 6.3 Markdown Report

**Filename:** `cve_report_YYYY-MM-DD.md`  
Compatible with GitHub, GitLab, Notion, Confluence, Obsidian.

```markdown
# CVE Scan Report — June 7 2026

## Summary
| Metric | Value |
|---|---|
| Packages scanned | 492 |
| Vulnerable | 17 |
| Attack Surface Score | 63/100 |
| KEV Matches | 1 |
| Critical | 2 |
| High | 5 |
| Medium | 8 |
| Low | 2 |

## 🔴 Actively Exploited (KEV Matches)
| Package | CVE ID | CVSS | EPSS | Risk Score |
|---|---|---|---|---|
| openssl 3.0.1 | CVE-2022-0778 | 9.8 | 97% | 89/100 |

## Critical Findings
...

## Remediation Table
| Package | Current | Safe Version |
|---|---|---|
...
```

### 6.4 TXT Report

**Filename:** `cve_report_YYYY-MM-DD.txt`  
Plain text — same as terminal output but written to file. No ANSI color codes. ASCII box-drawing for tables. Designed for email attachments, logging systems, and environments where markdown is not rendered.

```
CVE SCAN REPORT — June 7 2026
==============================

SUMMARY
  Packages scanned : 492
  Vulnerable       :  17
  Critical         :   2
  High             :   5
  Medium           :   8
  Low              :   2
  KEV Matches      :   1
  Attack Surface   : 63/100

ACTIVELY EXPLOITED
  openssl 3.0.1 — CVE-2022-0778 (CVSS 9.8) — ACTIVELY EXPLOITED IN THE WILD

CRITICAL FINDINGS
  ...
```

### 6.5 CSV Report

**Filename:** `cve_report_YYYY-MM-DD.csv`  
**Library:** Built-in `csv` module  
**Columns:**

```
package, version, ecosystem, cve_id, cvss_score, cvss_severity,
epss_score, epss_percent, kev_match, risk_heat_score,
dependency_type, reachability, description, fix_version,
published_date, nvd_url
```

Compatible with Excel, Google Sheets, pandas, Power BI, Splunk.

### 6.6 JSON Report

**Filename:** `cve_report_YYYY-MM-DD.json`

```json
{
  "scan_meta": {
    "timestamp": "2026-06-07T14:32:00",
    "hostname": "dev-machine",
    "tool_version": "4.0.0",
    "packages_scanned": 492,
    "attack_surface_score": 63
  },
  "summary": {
    "vulnerable": 17, "clean": 475,
    "critical": 2, "high": 5, "medium": 8, "low": 2,
    "kev_matches": 1
  },
  "findings": [
    {
      "package": "openssl",
      "version": "3.0.1",
      "ecosystem": "system-apt",
      "cve_id": "CVE-2022-0778",
      "cvss_score": 9.8,
      "cvss_severity": "CRITICAL",
      "epss_score": 0.97,
      "epss_percent": "97%",
      "kev_match": true,
      "risk_heat_score": 89,
      "dependency_type": "DIRECT",
      "reachability": "REACHABLE",
      "fix_version": "3.0.7",
      "description": "...",
      "published_date": "2022-03-15",
      "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2022-0778"
    }
  ]
}
```

### 6.7 Multi-Format CLI Export

```bash
cve-scan --auto-discover --output pdf,md,csv
cve-scan --file requirements.txt --output all
cve-scan --auto-discover --output json --report-dir ~/reports/ --report-name audit_q2
```

---

## 7. Threat Intelligence

### 7.1 NVD API v2

- Endpoint: `https://services.nvd.nist.gov/rest/json/cves/2.0`
- Hybrid matching: CPE version range bounds + keyword fallback
- Version evaluation via `packaging.version` (PEP 440)
- Rate limit: 5 req/30s (no key) · 50 req/30s (with key)
- Cache TTL: 24 hours in `~/.cve-scanner/cve_cache.db`

### 7.2 EPSS (Exploit Prediction Scoring System)

- Source: `https://api.first.org/data/v1/epss`
- Returns probability (0.0–1.0) of exploitation in next 30 days
- Batched: up to 100 CVE IDs per request
- Cache TTL: 6 hours
- Displayed as percentage in all outputs

### 7.3 CISA KEV (Known Exploited Vulnerabilities)

- Source: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- Downloaded once per 24 hours, stored locally
- Zero per-CVE API calls — all lookups from local cache
- KEV matches: `⚠ ACTIVELY EXPLOITED` badge, sorted to top of all outputs

### 7.4 Risk Heat Score

```
Risk Heat Score (0–100) =
    (CVSS_base / 10 × 50)
  + (EPSS_score × 30)
  + (KEV_match × 20)
```

Primary sort key in all output formats. A Critical CVE with low EPSS and no KEV match ranks below a High CVE that is in KEV and has 90% EPSS.

---

## 8. Auto-Discovery Engine

| Ecosystem | Detection method |
|---|---|
| Python | `importlib.metadata.distributions()` |
| Node.js | `package-lock.json` → `node_modules/` → `package.json` |
| Windows | `winget list` |
| Debian/Ubuntu | `dpkg-query -W` |
| RHEL/CentOS | `rpm -qa` |
| macOS | `brew list --versions` |

Discovery output:
```
Auto-discovering installed packages...

  Python (pip)    :  142 packages
  Node (npm)      :   38 packages
  System (apt)    :  312 packages

  Total: 492 packages to scan
```

---

## 9. CLI Command Reference

### 9.1 Interactive Mode

```bash
cve-scan           # launches banner + session menu
```

### 9.2 Direct Commands

```bash
cve-scan openssl 3.0.1                            # single package
cve-scan --auto-discover                          # all ecosystems
cve-scan --auto-discover --ecosystem python       # python only
cve-scan --auto-discover --ecosystem node
cve-scan --auto-discover --ecosystem system
cve-scan --file requirements.txt
cve-scan --file package.json
cve-scan --cve CVE-2022-0778
cve-scan --auto-discover --severity high
cve-scan --auto-discover --output pdf,md,csv
cve-scan --auto-discover --output all --report-name scan_june2026
cve-scan --watch 6
cve-scan --auto-discover --reachability-check ./src
cve-scan --set-key nvd YOUR_KEY_HERE
cve-scan --set-key slack https://hooks.slack.com/...
cve-scan --no-banner --auto-discover
cve-scan --auto-discover --no-interactive --output json
```

### 9.3 Full Flags Reference

| Flag | Type | Default | Description |
|---|---|---|---|
| *(no args)* | — | — | Interactive banner + menu |
| `package version` | positional | — | Scan single package |
| `--auto-discover` | bool | false | Auto-detect all installed packages |
| `--ecosystem` | string | all | python, node, system |
| `--file` | path | — | Scan from file |
| `--cve` | string | — | Direct CVE ID lookup |
| `--severity` | string | all | low, medium, high, critical |
| `--output` | string | table | table, pdf, md, txt, csv, json, all |
| `--report-name` | string | cve_report_YYYY-MM-DD | Output filename |
| `--report-dir` | path | ~/cve-reports/ | Output directory |
| `--api-key` | string | — | NVD API key (overrides .env) |
| `--set-key` | string string | — | `--set-key nvd KEY` |
| `--watch` | int | — | Watch mode interval (hours) |
| `--reachability-check` | path | — | Source dir for import analysis |
| `--ignore-file` | path | .cve-ignore | CVE ignore list |
| `--no-cache` | bool | false | Bypass local SQLite cache |
| `--no-banner` | bool | false | Skip ASCII banner |
| `--no-interactive` | bool | false | Force CI/pipe mode |
| `--project` | string | default | Named project scope |

---

## 10. Watch Mode & Posture History

```bash
cve-scan --watch 6    # runs every 6 hours
```

- Saves each scan to `~/.cve-scanner/posture_history.db`
- Computes delta diff on each run — only *new* CVEs trigger alerts
- Logs *remediated* CVEs (present before, gone now)
- Suppresses duplicate alerts — one notification per CVE unless KEV status changes

### posture_history.db Schema

```sql
CREATE TABLE scan_runs (
    id            INTEGER PRIMARY KEY,
    project       TEXT,
    timestamp     DATETIME,
    pkg_count     INTEGER,
    cve_count     INTEGER,
    surface_score INTEGER
);

CREATE TABLE cve_events (
    scan_run_id   INTEGER,
    cve_id        TEXT,
    package       TEXT,
    status        TEXT,   -- 'new' | 'persisting' | 'remediated'
    risk_score    INTEGER
);
```

---

## 11. Alert & Notification System

Configured via `~/.cve-scanner/.cve-alerts`:

```yaml
webhooks:
  - name: security-slack
    url: https://hooks.slack.com/services/...
    trigger:
      kev_match: true
      epss_threshold: 0.4
      cvss_threshold: 8.0
    format: slack

email:
  enabled: true
  smtp_host: smtp.example.com
  smtp_port: 587
  to: security@example.com
  schedule: weekly
```

**Triggers:** `kev_match`, `epss_threshold`, `cvss_threshold`, `new_critical`, `score_regression`

---

## 12. CI/CD Integration

**Exit codes:**
- `0` — no CVEs at or above configured severity threshold
- `1` — CVEs found that breach the threshold

**GitHub Actions example:**
```yaml
name: CVE Scan
on: [push, pull_request]
jobs:
  cve-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with: { python-version: "3.11" }
      - run: pip install -r requirements.txt
      - run: python cve_scanner.py --file requirements.txt --severity high --output json --no-interactive
        env:
          NVD_API_KEY: ${{ secrets.NVD_API_KEY }}
      - uses: actions/upload-artifact@v3
        with:
          name: cve-report
          path: cve_report.json
```

---

## 13. Project Structure

```
cve-scanner/
├── cve_scanner.py        # CLI entry point, banner, menu loop
├── banner.py             # ASCII art, gradient rendering
├── key_manager.py        # Interactive .env read/write, key validation
├── discoverer.py         # Multi-ecosystem auto-discovery
├── dep_graph.py          # Dependency tree, direct/transitive tagging
├── nvd_client.py         # NVD API v2, rate limiter, caching
├── threat_intel.py       # EPSS + KEV enrichment, Risk Heat Score
├── cache.py              # SQLite cache layer
├── watcher.py            # Watch mode daemon, baseline diff
├── notifier.py           # Webhook + email alerts
├── reporter.py           # PDF, MD, TXT, CSV, JSON exporters
├── models.py             # Package, CVEResult dataclasses
├── requirements.txt
├── .env.example
├── .cve-ignore.example
├── .cve-alerts.example
├── .github/
│   └── workflows/
│       └── cve-scan.yml
└── tests/
    ├── test_discoverer.py
    ├── test_nvd_client.py
    ├── test_threat_intel.py
    ├── test_reporter.py
    └── test_key_manager.py
```

---

## 14. Tech Stack

| Layer | Library |
|---|---|
| Terminal UI | `rich` |
| Interactive prompts | `questionary` |
| HTTP client | `httpx` |
| PDF generation | `reportlab` |
| HTML templating | `jinja2` |
| Version comparison | `packaging` |
| Caching & history | `sqlite3` (built-in) |
| Env config | `python-dotenv` |
| CLI parsing | `argparse` |
| Testing | `pytest` |

```bash
pip install rich questionary httpx reportlab jinja2 packaging python-dotenv pytest
```

---

## 15. Milestones

| Milestone | Deliverables | Target |
|---|---|---|
| M1 — Interactive Shell | Banner, menu loop, single scan, terminal table, JSON | Week 1 |
| M2 — Report Export | PDF, MD, TXT, CSV exporters in `reporter.py` | Week 2 |
| M3 — API Key Manager | `key_manager.py`, `.env` R/W, key validation, `--set-key` | Week 2 |
| M4 — Auto-Discovery | Python + Node + system discovery, dep graph | Week 3 |
| M5 — Threat Intel | EPSS + KEV enrichment, Risk Heat Score | Week 4 |
| M6 — Advanced Scan | Caching, fix recommendations, reachability, ignore list | Week 5 |
| M7 — Watch & Alerts | Watch daemon, posture history, webhooks, email | Week 6 |
| M8 — CI/CD | Non-interactive mode, exit codes, GitHub Actions workflow | Week 7 |

---

## 16. Performance

| Scenario | Estimated time |
|---|---|
| Single package (no cache) | < 3s |
| 200 packages, with NVD key | ~2 min |
| 200 packages, no NVD key | ~7 min |
| Export all 5 formats | < 15s |
| EPSS batch (200 CVEs) | ~3s (2 API calls) |
| KEV lookup (any count) | 0 network calls (local) |

---

## 17. Privacy & Data

- All data stays local. No telemetry. No cloud sync.
- Storage under `~/.cve-scanner/`:
  - `cve_cache.db` — NVD, EPSS, KEV cache
  - `posture_history.db` — scan run history
  - `.env` — API keys (chmod 600 on creation)
- EPSS and KEV queries transmit only CVE IDs — no package names leave the machine.

---

## 18. Out of Scope (This Version)

- Web dashboard or browser UI
- Docker image layer scanning (v2.1)
- Rust/Cargo, Java/Maven, Ruby/Gem (v2.1)
- Automatic code patching (suggested diffs only)
- Multi-user access control
- Cloud sync or remote storage
- Auto-PR generation for remediation (v3.0)

---

*Multi-ecosystem. Exploit-aware. Interactive. All local. — CVE Scanner CLI v4.0*
