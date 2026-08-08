# PULSE — Package & Unified Lifecycle Security Engine

A fast, developer-first, threat-aware vulnerability scanner and security intelligence CLI for software dependencies and web applications.

PULSE goes beyond theoretical CVSS scores by fusing multi-source threat intelligence (OSV, NVD, EPSS, CISA KEV, MITRE ATT&CK) to prioritize real-world security risks with a proprietary **Risk Heat Score** and actionable, evidence-verified remediation recommendations.

---

## Key Features

- ⚡ **Multi-Ecosystem Discovery:** Parses and inspects dependencies across **Python**, **Node.js**, **Rust (Cargo)**, **Go**, **Ruby (Gems)**, **PHP (Composer)**, and **Java (Maven)**.
- 🌐 **Website Technology & Vulnerability Assessment:** Passive fingerprinting of web frameworks, JS libraries, server software, and CMS platforms (React, Vue, Angular, Next.js, Nginx, Apache, WordPress) with HTTP security header analysis and vulnerability correlation.
- 🎯 **Threat-Aware Prioritization:** Sorts findings by the **Risk Heat Score** combining CVSS, EPSS 30-day exploit prediction probability, and CISA Known Exploited Vulnerability (KEV) active exploitation data.
- 🛡️ **Verified Upgrade Recommendations:** Recommends exact version pins (e.g. `pip install Django==6.1` or `npm install react@18.3.1`) verified against advisory history to ensure recommended versions are never vulnerable.
- 🗺️ **Human-Readable ATT&CK & CWE:** Displays official MITRE ATT&CK techniques (`T1190 — Exploit Public-Facing Application`) and CWE catalog names (`CWE-89 — SQL Injection`).
- 📄 **Cross-Format Exporters:** Export interactive HTML dashboards, JSON (Schema 2.0), Markdown, CSV, SARIF (CI/CD), and CycloneDX SBOM reports directly to `~/Documents/PULSE Reports/`.
- 🔍 **Interactive All Findings View:** Paginated, compact findings matrix supporting zero data loss across large datasets.
- 📊 **Security Posture & History Tracking:** SQLite-backed tracking of Attack Surface Score evolution across scans with automatic delta reports.
- 🌐 **Resilient Architecture:** Graceful degradation with local SQLite caching when network services are offline or rate-limited.

---

## Installation & Quick Start

### Prerequisites
- **Python:** Version 3.10 or higher (Python 3.11/3.12/3.14 recommended)
- **Git:** Installed on your system

### 1. Download / Clone the Repository
Open your terminal or command prompt and clone the repository:

```bash
git clone https://github.com/your-username/pulse.git
cd pulse
```

*(Alternatively, download the ZIP archive from GitHub and extract it to a directory on your machine.)*

### 2. Global Installation (Run `pulse` from Any Directory without Venv Activation)

To run `pulse` from any directory without needing to manually activate a virtual environment:

**On Linux / macOS (via `pipx` - Recommended):**
```bash
sudo apt update && sudo apt install -y pipx
pipx ensurepath
pipx install -e .
```
*(Or create a symlink: `ln -sf ~/Tools/pulse/venv/bin/pulse ~/.local/bin/pulse`)*

**On Windows (PowerShell / Command Prompt):**
```bash
pip install -e .
```
*(Installs `pulse.exe` directly into your system PATH Python Scripts directory).*

---

### 3. Virtual Environment Installation (Alternative)

If you prefer installing inside an isolated virtual environment:

**On Windows:**
```bash
python -m venv venv
.\venv\Scripts\activate
pip install -e .
```

**On Linux / macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

### 4. Run the Tool
Launch PULSE from any directory in your terminal:

```bash
pulse
```

---

## Subcommands & CLI Usage

### Subcommands
- `pulse config` — Manage settings (`pulse config list`, `pulse config get <KEY>`, `pulse config set <KEY> <VAL>`)
- `pulse doctor` — System health diagnostics (`pulse doctor`, `pulse doctor --json`)
- `pulse docs` — Generate CLI configuration documentation (`pulse docs config`)

### Command Flags
```bash
pulse --offline             # Force local cache scanning without network calls
pulse --verbose             # Display detailed score calculation breakdowns
pulse --compact             # Render compact executive summary
pulse --attack-paths        # Enable deep attack path exposure analysis
pulse --debug               # Enable diagnostic logging
```

---

## Threat Intelligence Pipeline

1. **Discovery:** Identifies installed and project manifest dependencies.
2. **OSV Provider:** Matches packages against Google OSV vulnerability database.
3. **NVD Provider:** Enriches findings with CVSS base scores, vectors, and severities.
4. **EPSS Layer:** Incorporates FIRST EPSS probability scores (0.0 to 1.0).
5. **CISA KEV Layer:** Checks for active exploitation status in CISA Known Exploited Vulnerabilities catalog.
6. **MITRE ATT&CK & CWE Registry:** Maps findings to technique IDs, titles, tactics, and CWE definitions.
7. **Risk Heat Score Calculation:**
   $$\text{Risk Heat Score} = (\text{CVSS} \times 5) + (\text{EPSS} \times 30) + (\text{KEV} \times 20)$$
8. **ScanPolicy & Verified Remediation:** Filters candidates, rejects vulnerable fix versions, and emits exact pinning upgrade commands.

---

## Configuration & NVD API Key

Configure options via interactive menu (`Settings`) or `pulse config`:

```bash
pulse config set NVD_API_KEY your_api_key_here
pulse config set REPORT_DEFAULT_LOCATION documents
```

By default, exported reports are saved to:
- **Windows:** `%USERPROFILE%\Documents\PULSE Reports\`
- **Linux/macOS:** `~/Documents/PULSE Reports/`

---

## License

GNU General Public License v3.0 (GPLv3). See [LICENSE](LICENSE) for details.
