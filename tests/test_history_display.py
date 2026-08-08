import pytest
from pulse.history import HistoryService

def test_history_display_formatting():
    history = HistoryService()
    runs = history.get_scan_runs()
    
    # Verify structure returned by get_scan_runs contains required target & integrity keys
    assert isinstance(runs, list)
    if runs:
        first = runs[0]
        assert "target_type" in first
        assert "target_id" in first
        assert "score" in first
        assert "vulns" in first
