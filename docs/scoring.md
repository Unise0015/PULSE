# Risk Scoring & Prioritization Methodology (Technical Deep Dive)

PULSE overrides standard CVSS scores with a context-aware **Risk Heat Score**.

## 1. Risk Heat Score Formula (0-100)
The composite Risk Heat Score is calculated in `pulse.vulnerability.threat_intel.RiskCalculator`.

`raw_score = (cvss_component + epss_component + kev_base) * m_kev`

Where:
- `cvss_component` = `(CVSS / 10.0) * 50`
- `epss_component` = `EPSS Probability * 30`
- `kev_base` = `20` (if `kev_match == True`) or `0`
- `m_kev` = Ransomware Multiplier (Tiered)

### The M_KEV Multiplier Algorithm
PULSE aggressively prioritizes known ransomware vectors.
- **No KEV match:** `1.00x` multiplier
- **KEV match, no ransomware:** `1.35x` multiplier
- **KEV match + Ransomware use (`knownRansomwareCampaignUse == "Known"`):** `1.69x` multiplier

The final score is capped: `Risk Heat Score = min(100, math.ceil(raw_score))`
