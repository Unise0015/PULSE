# Risk Scoring & Prioritization Methodology

PULSE uses a weighted **Risk Heat Score** formula designed to reflect true exploitation likelihood and operational risk rather than theoretical CVSS severity alone.

---

## 1. Risk Heat Score Formula (0–100)

The composite Risk Heat Score is calculated as follows:

$$\text{Risk Heat Score} = (\text{CVSS Base} \times 5.0) + (\text{EPSS Probability} \times 30.0) + (\text{KEV Active Multiplier} \times 20.0) + \text{PoC Adjustment}$$

### Component Weights:
1. **CVSS Base Score (50% max contribution, up to 50 pts):**
   - Measures theoretical technical impact and complexity.
2. **EPSS Exploit Probability (30% max contribution, up to 30 pts):**
   - Probability of active exploitation within 30 days (e.g. EPSS 0.85 = +25.5 pts).
3. **CISA KEV Active Exploitation (20% contribution, 20 pts):**
   - If the vulnerability is present in the CISA KEV catalog, 20 points are added immediately.
4. **Exploit PoC Adjustment (up to +10 pts):**
   - Functional / Weaponized public exploit: +10 pts.
   - Proof of Concept (PoC) available: +5 pts.

---

## 2. Severity Tiers

| Severity Tier | Score Range | Operational SLA / Recommendation |
| :--- | :--- | :--- |
| **CRITICAL** | **80.0 – 100.0** | Immediate remediation required. Active weaponization or critical CVSS + high EPSS. |
| **HIGH** | **60.0 – 79.9** | Remediate in current sprint. Weaponized PoC or high severity flaw. |
| **MEDIUM** | **30.0 – 59.9** | Schedule for standard maintenance cycle. Moderate impact without active exploitation. |
| **LOW** | **0.0 – 29.9** | Informational / Low risk. Address during regular updates. |

---

## 3. Attack Surface Score

The **Attack Surface Score** provides an aggregate risk index for an entire project or website target:

$$\text{Attack Surface Score} = \min\left(100, \sum_{i=1}^{n} \frac{\text{Finding Risk Score}_i}{\sqrt{n}} + \text{Exposure Penalty}\right)$$

- **Exposure Penalty:** Added for publicly exposed web technologies without security headers or unpinned direct dependencies.\n