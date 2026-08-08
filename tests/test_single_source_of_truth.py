import pytest
from datetime import datetime

from pulse.domain.models import ScanResult, VulnerabilityFinding, PackageInfo
from pulse.version_intelligence.models import UpgradeRecommendation
from pulse.reporting.builder import ReportBuilder
from pulse.reporting.context import ReportContext

def _make_test_scan():
    pkg = PackageInfo(name="Django", version="3.2", ecosystem="pypi")
    finding = VulnerabilityFinding(
        cve_id="CVE-2021-45452",
        package=pkg,
        cvss_score=8.5,
        cvss_severity="HIGH",
        fix_version="5.1.14",
        source="OSV"
    )
    scan = ScanResult(
        timestamp=datetime.now(),
        hostname="test",
        tool_version="1.0",
        packages_scanned=1,
        attack_surface_score=85,
        findings=[finding]
    )
    return scan, pkg, finding

def test_single_source_of_truth_instance_identity():
    scan, pkg, finding = _make_test_scan()

    mock_rec = UpgradeRecommendation(
        package_name="Django",
        ecosystem="pypi",
        current_version="3.2",
        minimum_known_safe="5.1.14",
        latest_stable="6.1",
        recommended_version="6.1",
        rejected_candidates=["5.1.14"],
        verified_safe=True
    )

    key = scan.make_package_key("pypi", "Django")
    scan.upgrade_recommendations[key] = mock_rec

    # 1. Verify get_recommendation returns exact same instance
    retrieved_rec = scan.get_recommendation("Django", "pypi")
    assert retrieved_rec is mock_rec

    # 2. Verify ReportBuilder uses exact same recommendation version & command
    ctx = ReportContext(scan_result=scan, scan_id="export")
    model = ReportBuilder.build(ctx)
    finding_model = model.findings[0]

    assert finding_model.fix_version == mock_rec.recommended_version
    assert mock_rec.recommended_version in finding_model.remediation_command
