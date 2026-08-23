# PULSE — Package & Unified Lifecycle Security Engine

![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)
![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)

PULSE is an easy-to-use command-line security tool that helps developers and security researchers quickly identify if they are using outdated or dangerous technologies. It scans your software projects, live websites, and local operating system, checking their specific versions against leading threat intelligence databases like **OSV** and **NVD** to find known security vulnerabilities and provide instant remediation advice directly in the terminal.

---

## 📑 Table of Contents
- [Key Features](#-key-features)
- [Intelligence Sources](#-intelligence-sources)
- [Installation](#-installation)
- [How to Use PULSE](#-how-to-use-pulse)
- [Configuration & API Keys](#-configuration--api-keys)
- [Developer Documentation](#-developer-documentation)

---

## ✨ Key Features

1. 📦 **Scan Software Projects**
   PULSE can scan your project files (like `requirements.txt`, `package.json`, `go.mod`, etc.) to find outdated packages that have known vulnerabilities.

2. 🌐 **Scan Websites**
   Just provide a URL, and PULSE will analyze the website to detect what technologies it's using (like React, Nginx, or PHP). It will then check if those technologies have any known security flaws.

3. 🖥️ **Scan Your Local System**
   PULSE can run a host system audit to check your operating system (currently supports Linux) for vulnerabilities.

4. 🔍 **Lookup CVEs**
   Look up specific CVE (Common Vulnerabilities and Exposures) IDs to get detailed information about a vulnerability directly from your terminal.

5. 📊 **Generate Reports**
   Export your scan results into multiple easy-to-read formats:
   - Interactive HTML Dashboard
   - JSON
   - Markdown
   - Plain Text

---

## 🧠 Intelligence Sources

To provide accurate and actionable security insights, PULSE cross-references discovered technologies against multiple leading vulnerability and threat intelligence databases:

- **OSV (Open Source Vulnerabilities):** The primary database used to find vulnerabilities in open-source packages (e.g., PyPI, npm, RubyGems).
- **NVD (National Vulnerability Database):** Used to check system infrastructure, OS packages, and web servers for vulnerabilities using CPE (Common Platform Enumeration) identifiers.
- **EPSS (Exploit Prediction Scoring System):** Provides the real-world probability that a specific vulnerability will be exploited in the wild within the next 30 days.
- **CISA KEV (Known Exploited Vulnerabilities):** Flags vulnerabilities that are currently being actively exploited by threat actors.

---

## 🚀 Installation

### Prerequisites
- **Python 3.11+**
- **pip** or **pipx**

### Linux / macOS

```bash
# 1. Clone the repository
git clone https://github.com/Unise0015/PULSE.git
cd PULSE

# 2. Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install in editable mode
pip install -e .

# 4. Launch PULSE
pulse
```

### Windows (PowerShell)

```powershell
# 1. Clone the repository
git clone https://github.com/Unise0015/PULSE.git
cd PULSE

# 2. Create and activate virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# 3. Install in editable mode
pip install -e .

# 4. Launch PULSE
pulse
```

---

## 💻 How to Use PULSE

To start the interactive menu, just type `pulse` in your terminal:

```bash
pulse
```

You will see an interactive menu like this:
```text
? What would you like to do?
 1) Scan a Package Across Any Supported Ecosystem
 2) Auto-discover & scan host system
 3) Scan from file (requirements.txt / package.json)
 4) Lookup a CVE ID directly
 5) Website Technology Assessment
 6) Export last scan report
 7) View scan history
 8) Settings
 h) Help
 0) Exit
```
*(Use your arrow keys to select an option and press Enter to run a scan.)*

### Command-Line Options & Flags
In addition to the interactive menu, you can pass flags directly to bypass the menu:

```bash
pulse --offline       # Execute using cached databases only (no external network calls)
pulse --verbose       # Show detailed candidate resolution scores and stage breakdowns
pulse --compact       # Output concise executive summary table only
pulse --attack-paths  # Automatically render MITRE ATT&CK exposure chains
pulse --debug         # Enable verbose debug logging and diagnostic stack traces
pulse --no-banner     # Suppress ASCII art startup banner
```

### System Health Diagnostics
If you are having issues running the tool, you can run a diagnostic health check:
```bash
pulse doctor          # Run interactive health checks with diagnostic scores
```

---

## ⚙️ Configuration & API Keys

### NVD API Key (Recommended)
An NVD API key increases the NIST NVD rate limit from **5 requests** to **50 requests** per 30-second rolling window. Since NVD is heavily used for system and website scanning, this is highly recommended:

1. Request a free key at [NIST NVD Developer Portal](https://nvd.nist.gov/developers/request-an-api-key).
2. Configure it in PULSE via any of the following methods:
   - **Interactive Menu:** `Settings` -> `API Keys & Credentials` -> `Add/Update NVD API Key`
   - **CLI Command:** `pulse config set NVD_API_KEY your_key_here`
   - **Environment Variable:** Set `NVD_API_KEY=your_key_here` in your environment.

---

## 📚 Developer Documentation

If you are a developer looking to understand the internal workings of PULSE (such as how we connect to OSV and NVD, or how our internal architecture operates), please check the [docs/](./docs/) folder in this repository.

---

## 📜 License

This project is licensed under the terms of the **GNU General Public License v3.0 (GPLv3)**. See the `LICENSE` file for details.
