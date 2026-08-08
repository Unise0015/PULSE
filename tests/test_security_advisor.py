"""Tests for SecurityAdvisor engine: prioritization, action plan, risk reduction."""
import pytest
from datetime import datetime
from pulse.domain.models import PackageInfo, VulnerabilityFinding, ScanResult
from pulse.security_advisor import SecurityAdvisor, classify_package_status


# ── Fixtures ───────────────────────────────────────────────────────────────────

def make_pkg(name, version, ecosystem="python", latest=None):
    return PackageInfo(
        name=name, version=version, ecosystem=ecosystem,
        latest_version=latest,
    )


def make_finding(pkg, cve_id, cvss_score=7.5, severity="HIGH",
                 risk=45, fix_version=None, epss=0.1):
    return VulnerabilityFinding(
        package=pkg,
        cve_id=cve_id,
        cvss_score=cvss_score,
        cvss_severity=severity,
        epss_score=epss,
        epss_percent=f"{int(epss*100)}%",
        kev_match=False,
        risk_heat_score=risk,
        description="Test vulnerability",
        fix_version=fix_version,
        source="OSV",
        published_date=None,
        last_modified_date=None,
        nvd_url="",
    )


def make_scan(findings, score=50):
    return ScanResult(
        timestamp=datetime.now(),
        hostname="test-host",
        tool_version="test",
        packages_scanned=10,
        attack_surface_score=score,
        scan_duration_seconds=1.0,
        findings=findings,
    )


# ── Advisor analysis ───────────────────────────────────────────────────────────

class TestSecurityAdvisorAnalysis:
    def test_empty_scan_returns_empty_report(self):
        scan = make_scan([])
        report = SecurityAdvisor().analyze(scan)
        assert report.actions == []

    def test_single_package_creates_one_action(self):
        pkg = make_pkg("django", "3.2", latest="5.2.1")
        f = make_finding(pkg, "CVE-2022-34265", cvss_score=9.8, severity="CRITICAL",
                         risk=77, fix_version="3.2.14")
        scan = make_scan([f], score=77)
        report = SecurityAdvisor().analyze(scan)

        assert len(report.actions) == 1
        action = report.actions[0]
        assert action.name == "django"
        assert action.cve_count == 1
        assert action.critical_count == 1
        assert action.min_safe == "3.2.14"
        assert action.target == "5.2.1"
        assert action.max_risk == 77

    def test_actions_sorted_by_max_risk_descending(self):
        pkg_a = make_pkg("requests", "2.27.0")
        pkg_b = make_pkg("django", "3.2")
        findings = [
            make_finding(pkg_a, "CVE-2023-1", risk=33, fix_version="2.31.0"),
            make_finding(pkg_b, "CVE-2022-1", risk=77, fix_version="3.2.14"),
        ]
        report = SecurityAdvisor().analyze(make_scan(findings))
        assert report.actions[0].name == "django"
        assert report.actions[1].name == "requests"

    def test_multiple_cves_same_package_counted(self):
        pkg = make_pkg("django", "3.2")
        findings = [
            make_finding(pkg, "CVE-2022-1", severity="CRITICAL", risk=77),
            make_finding(pkg, "CVE-2022-2", severity="HIGH",     risk=50),
            make_finding(pkg, "CVE-2022-3", severity="MEDIUM",   risk=30),
        ]
        report = SecurityAdvisor().analyze(make_scan(findings))
        assert len(report.actions) == 1
        action = report.actions[0]
        assert action.cve_count == 3
        assert action.critical_count == 1
        assert action.high_count == 1
        assert action.medium_count == 1
        assert action.max_risk == 77



# ── Command generation ─────────────────────────────────────────────────────────

class TestCommandGeneration:
    def test_recommended_python_command(self):
        pkg = make_pkg("django", "3.2", ecosystem="python")
        f = make_finding(pkg, "CVE-1", fix_version="3.2.14")
        report = SecurityAdvisor().analyze(make_scan([f]))
        action = report.actions[0]
        assert "--upgrade" in action.recommended_command


