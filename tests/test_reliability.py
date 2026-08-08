import os
import sqlite3
import shutil
import tempfile
from pathlib import Path
import pytest

from pulse.reporter import validate_export_path, ReportExportError
from pulse.website.website_fingerprint import validate_url
from pulse.history.db import init_db

def test_validate_export_path_success():
    temp_dir = tempfile.mkdtemp()
    try:
        target_path = Path(temp_dir) / "subfolder" / "report.html"
        valid_path = validate_export_path(target_path)
        assert valid_path == target_path
        assert target_path.parent.exists()
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_validate_export_path_is_dir_error():
    temp_dir = tempfile.mkdtemp()
    try:
        with pytest.raises(ReportExportError) as exc_info:
            validate_export_path(temp_dir)
        assert "directory" in str(exc_info.value).lower()
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_validate_url():
    valid, msg = validate_url("https://example.com")
    assert valid is True

    valid, msg = validate_url("ht!tp://invalid-url")
    assert valid is False
    assert "scheme" in msg.lower() or "invalid" in msg.lower()

    valid, msg = validate_url("ftp://example.com")
    assert valid is False
    assert "protocol" in msg.lower() or "scheme" in msg.lower()

    # External only policy
    valid, msg = validate_url("http://localhost:8080", external_only=True)
    assert valid is False
    assert "localhost" in msg.lower()

    valid, msg = validate_url("http://127.0.0.1:8000", external_only=True)
    assert valid is False
    assert "localhost" in msg.lower() or "private" in msg.lower() or "loopback" in msg.lower()


def test_db_migration_columns():
    temp_dir = tempfile.mkdtemp()
    try:
        db_file = Path(temp_dir) / "test_migration.db"
        init_db(db_file)

        with sqlite3.connect(db_file) as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(scan_runs)")
            cols = [row[1] for row in cursor.fetchall()]
            assert "scan_integrity" in cols
            assert "provider_status_json" in cols
            assert "warnings_json" in cols
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
