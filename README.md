# PULSE - Package & Unified Lifecycle Security Engine

PULSE is a command-line security scanner that discovers software dependencies across **9 package ecosystems**, correlates them against vulnerability databases (OSV, NVD), enriches findings with real-world threat intelligence (EPSS, CISA KEV, MITRE ATT&CK), and prioritizes risks using a weighted **Risk Heat Score** that reflects actual exploitation probability rather than static CVSS severity alone.

It also performs **passive website technology fingerprinting** with CPE-based vulnerability correlation, evaluates HTTP security headers, and exports results as HTML dashboards, SARIF for CI/CD, CycloneDX SBOM, JSON, or Markdown.

---

## Features

### Dependency Scanning
- **9 Ecosystems**: Python (pip), Node.js (npm), Rust (Cargo), Go, Ruby (Gems), PHP (Composer), Java (Maven), .NET (NuGet), GitHub Actions
- **Auto-Discovery**: Recursively detects manifest files in the current directory
- **Smart Detection**: Resolves ambiguous packages by querying 7 registries simultaneously (PyPI, npm, crates.io, Maven Central, NuGet, Packagist, RubyGems)
- **File Scanning**: Point at any requirements.txt, package.json, Cargo.lock, go.mod, Gemfile, composer.json, pom.xml, etc.

### Vulnerability Intelligence
- **OSV + NVD Correlation**: Dual-source vulnerability matching
- **EPSS Scoring**: 30-day exploit prediction probability from FIRST.org
- **CISA KEV Matching**: Flags actively exploited vulnerabilities
- **MITRE ATT&CK Mapping**: Maps CWE weaknesses to ATT&CK techniques
- **Exploit Intelligence**: Classifies PoC maturity (Active Exploitation, Weaponized, Functional PoC, Proof of Concept)
- **CWE Resolution**: Human-readable weakness names

### Risk Prioritization
- **Risk Heat Score**: Weighted formula combining CVSS (50%), EPSS (30%), KEV (20%)
- **Attack Path Analysis**: Exposure-scored vulnerability chains (KEV +40, EPSS>50% +25, CVSS>=9 +20, ATT&CK +10)
- **Attack Surface Score**: Aggregate risk metric per scan

### Website Assessment
- **Passive Fingerprinting**: Detects technologies via HTTP headers, cookies, HTML, script URLs
- **15 Signature Modules**: Angular, React, Vue, Svelte, Next.js, Vite, CDNs, CMS, WAFs, Runtimes, Libraries
- **Security Header Evaluation**: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, etc.
- **CPE Correlation**: Maps detected technologies to CVEs via NVD

### Remediation
- **Verified Upgrade Recommendations**: Queries registries for safe versions not themselves vulnerable
- **Ecosystem-Specific Commands**: Generates ready-to-run upgrade commands (pip install, npm install, etc.)
- **Branch Status**: Identifies Active, Maintenance, and End-of-Life versions

### Reporting & Export
- **HTML Dashboard**: Interactive report with risk cards and charts
- **SARIF 2.1.0**: CI/CD integration (GitHub Code Scanning compatible)
- **CycloneDX 1.4 SBOM**: Software Bill of Materials with Package URLs
- **JSON Schema 2.0**: Machine-readable structured output
- **Markdown**: GitHub-flavored report

### History & Posture Tracking
- **Scan History**: SQLite-backed history of all scans with delta tracking
- **Posture Delta**: Tracks new/remediated CVEs, risk score changes between scans
- **Report Artifact Registry**: Tracks all exported report files
- **Configurable Retention**: Max scans, retention days, auto-cleanup

---

## Installation

### Prerequisites

- **Python 3.11 or higher**
- **pip** package manager
- **Internet access** (for vulnerability database queries; offline mode available with cached data)

### Linux / macOS

```bash
# Clone the repository
git clone https://github.com/Unise0015/PULSE.git
cd PULSE

# Create virtual environment (required on modern Linux)
python3 -m venv venv
source venv/bin/activate

# Install in editable mode
pip install -e .

# Run PULSE
pulse
```

### Windows

```powershell
# Clone the repository
git clone https://github.com/Unise0015/PULSE.git
cd PULSE

# Enable script execution (if not already enabled)
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned

# Create virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install in editable mode
pip install -e .

# Run PULSE
pulse
```

### Without Virtual Environment (System-Wide)

```bash
# Linux/macOS (requires --break-system-packages on managed environments)
pip install --break-system-packages -e .

# Windows
pip install -e .
```

### Kali Linux (Externally Managed Environment)

Kali Linux restricts system-wide pip installations. Use a virtual environment:

```bash
cd PULSE
python3 -m venv venv
source venv/bin/activate
pip install -e .
pulse
```

Or use pipx for isolated installation:

```bash
pipx install .
pulse
```

---

## Quick Start

### Interactive Mode

```bash
pulse
```

Launches the interactive menu:

```
1. Scan a Package Across Any Supported Ecosystem
2. Auto-discover & scan all packages
3. Scan from file (requirements.txt / package.json)
4. Lookup a CVE ID directly
5. Website Technology Assessment
6. Export last scan report
7. View scan history
8. Settings
h. Help
0. Exit
```

### Command-Line Flags

```bash
pulse --offline      # Use cached data only (no network calls)
pulse --verbose      # Extended diagnostic output
pulse --compact      # Compact executive summary
pulse --attack-paths # Show attack path exposure analysis
pulse --debug        # Enable debug logging
pulse --no-banner    # Skip ASCII art banner
```

### Subcommands

```bash
# Configuration management
pulse config list          # List all settings
pulse config set KEY VALUE # Update a setting
pulse config diff          # Show non-default settings
pulse config validate      # Validate configuration file
pulse config reset         # Reset to defaults

# System diagnostics
pulse doctor               # Health check with scored results
pulse doctor --json        # Export diagnostics as JSON

# Documentation
pulse docs config          # Generate configuration reference
```

---

## Configuration

### NVD API Key (Recommended)

An NVD API key increases rate limits from 5 to 50 requests per 30-second window:

1. Register at https://nvd.nist.gov/developers/request-an-api-key
2. Add to PULSE:
   - Via interactive menu: Settings > API Keys & Credentials > Add/Update NVD API Key
   - Via command: `pulse config set NVD_API_KEY your-key-here`
   - Via .env file: Copy `.env.example` to `.env` and set `NVD_API_KEY=your-key-here`

### Configuration File

PULSE stores settings in a `.env` file in the platform config directory:
- **Linux/macOS**: `~/.config/pulse/.env`
- **Windows**: `%APPDATA%\pulse\.env`

See `.env.example` for all available settings.

---

## Supported Ecosystems

| Ecosystem | Manifest Files |
|---|---|
| Python (pip) | requirements.txt, requirements.in, Pipfile, pyproject.toml |
| Node.js (npm) | package.json, package-lock.json, yarn.lock, pnpm-lock.yaml |
| Rust (Cargo) | Cargo.toml, Cargo.lock |
| Go | go.mod, go.sum |
| Ruby (Bundler) | Gemfile, Gemfile.lock |
| PHP (Composer) | composer.json, composer.lock |
| Java (Maven) | pom.xml |
| .NET (NuGet) | .csproj, packages.config |
| GitHub Actions | .github/workflows/*.yml |

---

## Data Sources

| Source | Purpose | API |
|---|---|---|
| OSV | Vulnerability matching | https://api.osv.dev |
| NVD | CVSS scores, descriptions, CWE | https://services.nvd.nist.gov |
| EPSS | Exploit probability scores | https://api.first.org |
| CISA KEV | Active exploitation catalog | CISA JSON feed |

---

## Export Formats

| Format | Use Case |
|---|---|
| HTML Dashboard | Executive reporting, browser-based review |
| SARIF 2.1.0 | GitHub Code Scanning, CI/CD pipelines |
| CycloneDX 1.4 | SBOM compliance, supply chain management |
| JSON | API integration, automation |
| Markdown | Documentation, GitHub issues |

---

## Architecture

```
CLI (cli.py) -> ScannerOrchestrator (scanner.py)
    |
    +-> ScanService (auto-discover)
    +-> PackageService (targeted scan)
    +-> WebsiteService (website assessment)
         |
         +-> EnrichmentPipeline (10 stages)
              Version -> OSV -> NVD -> EPSS -> MITRE
              -> KEV -> Risk -> Exploit -> AttackPath -> Remediation
```

---

## Dependencies

| Package | Purpose |
|---|---|
| rich | Terminal UI rendering |
| questionary | Interactive prompts |
| httpx | HTTP client |
| jinja2 | Report templates |
| packaging | Version parsing |
| python-dotenv | Configuration loading |
| reportlab | PDF support |

---

## License

GNU General Public License v3.0 (GPLv3). See [LICENSE](LICENSE) for details.
