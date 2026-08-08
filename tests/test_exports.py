import pytest
import os
import json
import csv
from pathlib import Path
from pulse.reporter import generate_mock_scan_data, export_json, export_csv, export_markdown, export_html, export_sarif

def test_export_json(tmp_path):
    scan = generate_mock_scan_data()
    out_file = tmp_path / "report.json"
    export_json(scan, out_file)
    
    assert out_file.exists()
    with open(out_file, "r") as f:
        data = json.load(f)
        assert "scan_meta" in data
        assert "summary" in data
        assert "findings" in data
        assert len(data["findings"]) == len(scan.findings)

def test_export_csv(tmp_path):
    scan = generate_mock_scan_data()
    out_file = tmp_path / "report.csv"
    export_csv(scan, out_file)
    
    assert out_file.exists()
    with open(out_file, "r", newline='') as f:
        reader = csv.reader(f)
        headers = next(reader)
        assert "cve_id" in headers
        assert "risk_heat_score" in headers
        
        rows = list(reader)
        assert len(rows) == len(scan.findings)

def test_export_markdown(tmp_path):
    scan = generate_mock_scan_data()
    out_file = tmp_path / "report.md"
    export_markdown(scan, out_file)
    
    assert out_file.exists()
    with open(out_file, "r") as f:
        content = f.read()
        assert "# PULSE Security Scan Report" in content
        assert "Attack Surface Score" in content

def test_export_html(tmp_path):
    scan = generate_mock_scan_data()
    out_file = tmp_path / "report.html"
    export_html(scan, out_file)
    
    assert out_file.exists()
    with open(out_file, "r", encoding="utf-8") as f:
        content = f.read()
        assert "<!DOCTYPE html>" in content
        assert "PULSE Security Dashboard" in content

def test_export_sarif(tmp_path):
    scan = generate_mock_scan_data()
    out_file = tmp_path / "report.sarif.json"
    export_sarif(scan, out_file)
    
    assert out_file.exists()
    with open(out_file, "r", encoding="utf-8") as f:
        content = f.read()
        data = json.loads(content)
        assert data["version"] == "2.1.0"
        assert "$schema" in data
        assert len(data["runs"]) == 1
        assert "tool" in data["runs"][0]
        assert "results" in data["runs"][0]
        assert len(data["runs"][0]["results"]) == len(scan.findings)
