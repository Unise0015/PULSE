import pytest
from datetime import datetime
from pulse.domain.models import ScanResult, VulnerabilityFinding, PackageInfo
from pulse.history import HistoryService

def test_posture_delta_calculation(monkeypatch):
    history = HistoryService()
    
    pkg = PackageInfo("test", "1.0", "python", "DIRECT", "UNKNOWN")
    
    # We need to mock SQLite db behavior for unit test, or use an in-memory DB.
    # To keep this simple and isolated, we can just mock the cursor execution.
    class MockCursor:
        def execute(self, *args, **kwargs): pass
        def fetchone(self): return (1, 50, 0, 1) # id=1, score=50, kev=0, pkgs=1
        def fetchall(self): return [("CVE-OLD-1", 60), ("CVE-REMEDIATED", 85)]
    
    class MockConn:
        def cursor(self): return MockCursor()
        def commit(self): pass
        def __enter__(self): return self
        def __exit__(self, *args): pass
        
    import sqlite3
    monkeypatch.setattr(sqlite3, "connect", lambda x: MockConn())
    
    # New scan has CVE-OLD-1 and CVE-NEW-1. So CVE-REMEDIATED is gone.
    findings = [
        VulnerabilityFinding(pkg, "CVE-OLD-1", 5.0, "MEDIUM", 0.1, "10%", False, 60, "old finding", None, "OSV", "2023", "2023", ""),
        VulnerabilityFinding(pkg, "CVE-NEW-1", 9.0, "CRITICAL", 0.9, "90%", True, 95, "new critical finding", None, "OSV", "2023", "2023", "")
    ]
    
    scan = ScanResult(
        timestamp=datetime.now(),
        hostname="test",
        tool_version="1.0",
        packages_scanned=1,
        attack_surface_score=75,
        scan_duration_seconds=1.0,
        findings=findings
    )
    
    delta = history.get_posture_delta(scan)
    
    assert delta is not None
    assert delta.previous_score == 50
    assert delta.current_score == 75
    assert delta.risk_score_change == 25
    assert delta.kev_change_count == 1
    
    assert len(delta.new_cves) == 1
    assert delta.new_cves[0].cve_id == "CVE-NEW-1"
    
    assert len(delta.remediated_cves) == 1
    assert delta.remediated_cves[0] == "CVE-REMEDIATED"
    
    assert delta.highest_new_risk.cve_id == "CVE-NEW-1"
    assert delta.highest_resolved_cve == "CVE-REMEDIATED"
    assert delta.highest_resolved_risk_score == 85


def test_target_specific_posture_delta(monkeypatch):
    history = HistoryService()
    
    db_calls = []
    class MockCursor:
        def execute(self, query, params=()):
            db_calls.append((query, params))
        def fetchone(self):
            return (1, 50, 0, 1) # id=1, score=50, kev=0, pkgs=1
        def fetchall(self):
            return [("CVE-OLD-1", 60)]
            
    class MockConn:
        def cursor(self): return MockCursor()
        def commit(self): pass
        def __enter__(self): return self
        def __exit__(self, *args): pass
        
    import sqlite3
    monkeypatch.setattr(sqlite3, "connect", lambda x: MockConn())
    
    pkg = PackageInfo("flask", "2.1.0", "python", "DIRECT", "UNKNOWN")
    findings = [
        VulnerabilityFinding(pkg, "CVE-OLD-1", 5.0, "MEDIUM", 0.1, "10%", False, 60, "old finding", None, "OSV", "2023", "2023", ""),
    ]
    
    scan = ScanResult(
        timestamp=datetime.now(),
        hostname="test",
        tool_version="1.0",
        packages_scanned=1,
        attack_surface_score=60,
        scan_duration_seconds=1.0,
        findings=findings,
        target_type="package",
        target_id="pypi:flask",
        target_fingerprint="flask@2.1.0"
    )
    
    delta = history.get_posture_delta(scan)
    assert delta is not None
    assert delta.previous_score == 50
    assert delta.current_score == 60
    
    select_queries = [call for call in db_calls if "SELECT" in call[0]]
    assert len(select_queries) > 0
    query_str, params = select_queries[0]
    assert "target_type = ?" in query_str
    assert "target_id = ?" in query_str
    assert params[0] == "package"
    assert params[1] == "pypi:flask"
