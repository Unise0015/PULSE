# Vulnerability Scoring

CVE Scanner CLI uses a proprietary algorithm called the **Risk Heat Score** to rank and prioritize vulnerabilities.

## The Risk Heat Score Formula

```text
Risk Heat Score = (CVSS / 10 * 50) + (EPSS * 30) + (KEV * 20)
```

The maximum score is 100.

### Breakdown of the Components

1. **CVSS (Common Vulnerability Scoring System) [Max: 50 points]**
   - **What it is:** The theoretical severity of a vulnerability based on its technical characteristics (e.g., network vector, privileges required, impact on confidentiality/integrity/availability).
   - **Why it matters:** It provides the baseline technical impact.
   - **Weight:** 50%. While important, CVSS alone is insufficient because it doesn't measure whether an exploit actually exists in the wild.

2. **EPSS (Exploit Prediction Scoring System) [Max: 30 points]**
   - **What it is:** A data-driven probability (0 to 1) estimating the likelihood that a vulnerability will be exploited in the wild within the next 30 days.
   - **Why it matters:** EPSS focuses on *threat* rather than just *vulnerability*. A High CVSS score with a 0.001% EPSS score is less of an immediate risk than a Medium CVSS score with an 85% EPSS score.
   - **Weight:** 30%. This heavily biases the ranking towards vulnerabilities that attackers are actively researching or targeting.

3. **CISA KEV (Known Exploited Vulnerabilities) [Max: 20 points]**
   - **What it is:** A catalog maintained by the U.S. Cybersecurity and Infrastructure Security Agency containing vulnerabilities that have been definitively proven to be exploited in the wild.
   - **Why it matters:** If a CVE is on this list, it is no longer theoretical. It is an active, confirmed threat.
   - **Weight:** 20% flat penalty.

## Why is Risk Heat Score better than CVSS alone?

Traditional scanners sort by CVSS. The problem with this approach is "alert fatigue." A scan might return 50 "High" and "Critical" vulnerabilities, overwhelming developers. However, statistics show that only ~5% of published CVEs are ever actually exploited.

By combining CVSS (Technical Severity) with EPSS (Likelihood) and KEV (Confirmed Evidence), the **Risk Heat Score** answers the most important question in cybersecurity:

> *"Which vulnerability should I fix first?"*

## Attack Surface Score

The overarching metric for a scan is the **Attack Surface Score**.

```text
Attack Surface Score = Average Risk Score + (KEV Matches * 10)
```
*(Capped at 100)*

This score gives a high-level view of the environment's posture. A rising score indicates an accumulating technical debt of high-risk vulnerabilities.
