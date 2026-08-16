# MITRE ATT&CK Enterprise Matrix Mapping

PULSE integrates the MITRE ATT&CK framework to translate Common Weakness Enumerations (CWEs) into actionable adversary Tactics, Techniques, and Procedures (TTPs).

---

## 1. CWE to ATT&CK Technique Correlation

| CWE ID | Common Weakness | MITRE ATT&CK Technique | Tactic |
| :--- | :--- | :--- | :--- |
| **CWE-89** | SQL Injection | **T1190** – Exploit Public-Facing Application | Initial Access |
| **CWE-78** | OS Command Injection | **T1059** – Command and Scripting Interpreter | Execution |
| **CWE-79** | Cross-Site Scripting (XSS) | **T1189** – Drive-by Compromise | Initial Access |
| **CWE-22** | Path Traversal | **T1083** – File and Directory Discovery | Discovery |
| **CWE-502** | Deserialization of Untrusted Data | **T1059** – Command and Scripting Interpreter | Execution |
| **CWE-287** | Improper Authentication | **T1078** – Valid Accounts | Defense Evasion |
| **CWE-269** | Improper Privilege Management | **T1068** – Exploitation for Privilege Escalation | Privilege Escalation |
| **CWE-918** | Server-Side Request Forgery (SSRF) | **T1190** – Exploit Public-Facing Application | Initial Access |\n