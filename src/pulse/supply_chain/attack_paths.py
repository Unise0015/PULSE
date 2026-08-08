from typing import List
from pulse.domain.models import ScanResult, AttackPath, FindingSourceType

class AttackPathAnalyzer:
    """Analyzes and prioritizes attack paths based on exposure scoring."""

    @classmethod
    def generate(cls, scan: ScanResult) -> None:
        """
        Generates AttackPath objects from the ScanResult findings
        and attaches them to scan.attack_paths, sorted by exposure score desc.
        """
        paths = []
        seen = set()
        
        for f in scan.findings:
            key = (f.package.name, f.cve_id)
            if key in seen:
                continue
            seen.add(key)
            
            score = 0
            
            # KEV Match +40
            if f.kev_match:
                score += 40
                
            # EPSS > 50% +25
            if f.epss_score > 0.5:
                score += 25
                
            # CVSS (Exclusive)
            if f.cvss_score >= 9.0:
                score += 20
            elif f.cvss_score >= 7.0:
                score += 10
                
            # MITRE Mapping +10
            tactics = []
            if getattr(f, "attack_techniques", None):
                score += 10
                tactics = list(set([t.tactic for t in f.attack_techniques]))
                
            intel = getattr(f, "exploit_intelligence", None)
            exploit_maturity = intel.exploit_maturity if intel else "Unknown"
            
            path = AttackPath(
                package_name=f.package.name,
                package_version=f.package.version,
                cve_id=f.cve_id,
                cwe=f.cwe,
                attack_techniques=f.attack_techniques,
                attack_tactics=tactics,
                cvss_score=f.cvss_score,
                epss_score=f.epss_score,
                kev_match=f.kev_match,
                risk_score=f.risk_heat_score,
                exposure_score=score,
                exploit_maturity=exploit_maturity,
                source_type=getattr(f, "source_type", FindingSourceType.PACKAGE)
            )
            paths.append(path)
            
        # Sort descending by exposure score
        paths.sort(key=lambda x: x.exposure_score, reverse=True)
        scan.attack_paths = paths

