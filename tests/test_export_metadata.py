import pytest
import json
import csv
from pathlib import Path
from datetime import datetime

from pulse.domain.models import ScanResult, PackageInfo, VulnerabilityFinding
from pulse.reporter import export_json, export_csv


def test_export_metadata_embedding(tmp_path):
    pkg = PackageInfo(name="lodash", version="4.17.15", ecosystem="npm")
    finding = VulnerabilityFinding(
        package=pkg,
        cve_id="CVE-2020-8203",
        cvss_score=7.4,
        cvss_severity="HIGH",
        cwe="CWE-1321",
        source="OSV"
    )

    scan = ScanResult(
        timestamp=datetime.now(),
        hostname="test-host",
        tool_version="4.0.0",
        packages_scanned=1,
        attack_surface_score=40,
        scan_duration_seconds=1.25,
        findings=[finding]
    )

    json_path = tmp_path / "report.json"
    export_json(scan, json_path)
    
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert "scan_meta" in data
    assert data["scan_meta"]["tool_version"] == "4.0.0"
    assert "scan_integrity" in data["scan_meta"]
    assert "att_ck_coverage" in data["scan_meta"]
    assert "cwe_coverage" in data["scan_meta"]
    assert "provider_statistics" in data
    assert "validation_summary" in data

    csv_path = tmp_path / "report.csv"
    export_csv(scan, str(csv_path))

    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        rows = list(reader)

    header = rows[0]
    assert "cwe_id" in header
    assert "cwe_name" in header
    assert rows[1][header.index("cwe_id")] == "CWE-1321"
