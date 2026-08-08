import pytest
import sqlite3
import json
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta
from pulse.vulnerability.osv_provider import OSVProvider
from pulse.history.db import get_db_path

def test_osv_cache_expiry():
    """Test that expired cache entries are ignored."""
    provider = OSVProvider()
    
    # Mock the database cursor
    mock_cursor = MagicMock()
    
    # Set timestamp to 48 hours ago (expired)
    old_timestamp = (datetime.now() - timedelta(hours=48)).strftime("%Y-%m-%d %H:%M:%S")
    valid_json = json.dumps({"vulns": []})
    
    mock_cursor.fetchone.return_value = (valid_json, old_timestamp)
    
    result = provider._read_cache(mock_cursor, "test_key")
    assert result is None

def test_osv_cache_corruption_recovery():
    """Test that corrupted cache entries are deleted and ignored."""
    provider = OSVProvider()
    
    mock_cursor = MagicMock()
    
    recent_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    invalid_json = "{bad_json:"
    
    mock_cursor.fetchone.return_value = (invalid_json, recent_timestamp)
    
    result = provider._read_cache(mock_cursor, "test_key")
    
    assert result is None
    # Verify that DELETE was called to purge the corrupted entry
    mock_cursor.execute.assert_any_call("DELETE FROM osv_cache WHERE query_key = ?", ("test_key",))
