import pytest
from datetime import datetime
from pulse.domain.models import ScanResult, VulnerabilityFinding, PackageInfo, ExploitIntelligence, deduplicate_and_merge_findings
from pulse.history import HistoryService


class TestHistoryFindingDeduplication:
    """Component 5 & Bug 6, 7, 12, 23 – Tests deduplication and merging of duplicate CVE findings."""

    def test_deduplicate_and_merge_findings_semantics(self):
        pkg = PackageInfo(name="Django", version="3.2", ecosystem="pypi")

        # Record A: CVSS & CWE
        f1 = VulnerabilityFinding(
            package=pkg,
            cve_id="CVE-2022-34265",
            cvss_score=9.8,
            cvss_severity="CRITICAL",
            epss_score=0.0,
            epss_percent="0%",
            cwe="CWE-89",
            description="SQL Injection in Django"
        )

        # Record B: EPSS, KEV, PoC
        f2 = VulnerabilityFinding(
            package=pkg,
            cve_id="CVE-2022-34265",
            cvss_score=0.0,
            cvss_severity="UNKNOWN",
            epss_score=0.75,
            epss_percent="92%",
            kev_match=True,
            exploit_intelligence=ExploitIntelligence(public_poc=True, poc_source="GitHub", exploit_maturity="High")
        )

        # Record C: Different CVE
        f3 = VulnerabilityFinding(
            package=pkg,
            cve_id="CVE-2021-35042",
            cvss_score=8.5,
            cvss_severity="HIGH",
            epss_score=0.1,
            epss_percent="15%"
        )

        raw_findings = [f1, f2, f3, f3]

        merged = deduplicate_and_merge_findings(raw_findings)
        assert len(merged) == 2, f"Expected 2 unique findings, got {len(merged)}"

        cve_map = {f.cve_id: f for f in merged}
        assert "CVE-2022-34265" in cve_map
        assert "CVE-2021-35042" in cve_map

        # Verify merged enrichment fields
        django_cve = cve_map["CVE-2022-34265"]
        assert django_cve.cvss_score == 9.8
        assert django_cve.cvss_severity == "CRITICAL"
        assert django_cve.epss_score == 0.75
        assert django_cve.epss_percent == "92%"
        assert django_cve.kev_match is True
        assert django_cve.cwe == "CWE-89"
        assert django_cve.exploit_intelligence is not None
        assert django_cve.exploit_intelligence.public_poc is True

    def test_history_save_and_reload_deduplication(self):
        history = HistoryService()
        pkg = PackageInfo(name="requests", version="2.27.0", ecosystem="pypi")

        f1 = VulnerabilityFinding(
            package=pkg,
            cve_id="CVE-2023-32681",
            cvss_score=6.1,
            cvss_severity="MEDIUM",
            description="Proxy Authorization Header Leak"
        )
        f2 = VulnerabilityFinding(
            package=pkg,
            cve_id="CVE-2023-32681",
            cvss_score=6.1,
            cvss_severity="MEDIUM",
            description="Proxy Authorization Header Leak"
        )

        scan = ScanResult(
            timestamp=datetime.now(),
            hostname="testhost",
            tool_version="4.0.0",
            packages_scanned=1,
            attack_surface_score=61,
            scan_duration_seconds=0.5,
            findings=[f1, f2]
        )

        scan_id = history.save_scan(scan)
        reloaded_scan = history.get_scan_by_id(scan_id)

        assert reloaded_scan is not None
        assert len(reloaded_scan.findings) == 1, f"Expected 1 unique finding in history, got {len(reloaded_scan.findings)}"
        assert reloaded_scan.findings[0].cve_id == "CVE-2023-32681"
