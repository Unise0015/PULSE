# Attack Path & Exposure Analysis

PULSE models attacker movement and vulnerability exposure using MITRE ATT&CK technique chains and exposure scoring.

---

## 1. Attack Path Scoring Formula

Each vulnerability finding is scored for attack chain exploitability based on four key exposure vectors:

| Exposure Vector | Condition | Point Weight |
| :--- | :--- | :--- |
| **Active Exploitation** | Present in CISA KEV | **+40 points** |
| **High Exploit Probability** | EPSS Probability > 0.50 | **+25 points** |
| **Critical Technical Impact** | CVSS Base Score $\ge 9.0$ | **+20 points** |
| **Adversarial TTP Available** | MITRE ATT&CK Technique mapped | **+10 points** |

---

## 2. MITRE ATT&CK Technique Mapping

When a vulnerability is mapped to a CWE weakness, PULSE correlates it with enterprise attack chains:

```
[Initial Access] ──────► [Execution / Privilege Escalation] ──────► [Impact / Exfiltration]
      │                                    │                                    │
  T1190: Exploit                    T1068: Exploitation                 T1499: Endpoint Denial
  Public-Facing Application         for Privilege Escalation             of Service
```\n