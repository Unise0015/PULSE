# Attack Path & Exposure Analysis (Technical Deep Dive)

PULSE models attacker movement using MITRE ATT&CK technique chains and exposure scoring via the `AttackPathAnalyzer` class in `pulse.supply_chain.attack_paths`.

## 1. Attack Path Exposure Formula

Each `VulnerabilityFinding` is assigned an `exposure_score` (cumulative integer).

| Exposure Vector | Condition (`pulse.supply_chain.attack_paths`) | Point Weight |
| :--- | :--- | :--- |
| **Active Exploitation** | `finding.kev_match == True` | **+40 points** |
| **High Exploit Probability** | `finding.epss_score > 0.50` | **+25 points** |
| **Critical Technical Impact** | `finding.cvss_score >= 9.0` | **+20 points** |
| **High Technical Impact** | `finding.cvss_score >= 7.0` | **+10 points** |
| **Adversarial TTP Available** | `len(finding.attack_techniques) > 0` | **+10 points** |

### Execution Flow
1. The `ScannerOrchestrator` triggers `AttackPathAnalyzer.generate(scan)`.
2. The analyzer iterates over `scan.findings`. 
3. It utilizes a `set` to deduplicate by `(package.name, cve_id)` to prevent redundant node exposure bloat.
4. It initializes an `AttackPath` dataclass and appends it to `scan.attack_paths`, sorted descending by `exposure_score`.
