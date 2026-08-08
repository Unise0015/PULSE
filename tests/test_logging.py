import os
import shutil
import tempfile
from pathlib import Path
from unittest.mock import patch

from pulse.core.logging_config import (
    setup_logging,
    get_logger,
    set_scan_correlation_id,
    get_scan_correlation_id,
    SecretRedactionFilter
)

def test_secret_redaction_filter():
    filter_inst = SecretRedactionFilter()
    
    # Redact NVD API key and secrets
    text = "Fetching NVD API with apiKey=12345-abcde-secret and Bearer eyJhbGciOiJIUzI1NiJ9"
    redacted = filter_inst.redact(text)
    assert "12345-abcde-secret" not in redacted
    assert "[REDACTED]" in redacted
    assert "eyJhbGciOiJIUzI1NiJ9" not in redacted

    # Redact JSON secret payload
    json_text = '{"nvd_api_key": "secret-key-99", "password": "super-secret-pass"}'
    redacted_json = filter_inst.redact(json_text)
    assert "secret-key-99" not in redacted_json
    assert "super-secret-pass" not in redacted_json
    assert "[REDACTED]" in redacted_json


def test_scan_correlation_id():
    cid = set_scan_correlation_id("Scan 20260803-TEST")
    assert get_scan_correlation_id() == "Scan 20260803-TEST"
    assert cid == "Scan 20260803-TEST"


def test_setup_logging_file_creation():
    temp_dir = tempfile.mkdtemp()
    try:
        with patch("pulse.core.logging_config.get_config_dir", return_value=Path(temp_dir)):
            log_file = setup_logging(debug=True)
            logger = get_logger("test_module")
            logger.info("Test log message with token=supersecrettoken")

            assert log_file.exists()
            content = log_file.read_text(encoding="utf-8")
            assert "Test log message" in content
            assert "supersecrettoken" not in content
            assert "[REDACTED]" in content
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
