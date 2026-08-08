import pytest
import os
import shutil
from pathlib import Path
from unittest.mock import patch, MagicMock

from pulse.config import load_config, get_env_file_path, _validate_env_file

@pytest.fixture
def mock_env_path(tmp_path):
    env_file = tmp_path / ".env"
    with patch("pulse.config.get_env_file_path", return_value=env_file):
        yield env_file

def test_missing_env_creates_default(mock_env_path):
    # Ensure it's missing
    if mock_env_path.exists():
        mock_env_path.unlink()
        
    load_config()
    
    assert mock_env_path.exists()
    content = mock_env_path.read_text(encoding="utf-8")
    assert "DEFAULT_SEVERITY=" in content
    assert "DEFAULT_OUTPUT=table" in content
    assert "NVD_API_KEY=" in content

def test_empty_env_loads_successfully(mock_env_path):
    # Empty file
    mock_env_path.write_text("", encoding="utf-8")
    
    load_config()
    
    # Should not be modified (or backup created)
    content = mock_env_path.read_text(encoding="utf-8")
    assert content == ""
    # Check no backups exist
    backups = list(mock_env_path.parent.glob(".env.corrupted.*"))
    assert len(backups) == 0

def test_malformed_dotenv_recreates(mock_env_path):
    # Malformed syntax
    mock_env_path.write_text("INVALID LINE HERE\nVALID=123", encoding="utf-8")
    
    load_config()
    
    # File should be recreated
    content = mock_env_path.read_text(encoding="utf-8")
    assert "DEFAULT_SEVERITY=" in content
    assert "INVALID LINE HERE" not in content
    
    # Backup should exist
    backups = list(mock_env_path.parent.glob(".env.corrupted.*"))
    assert len(backups) == 1
    
    backup_content = backups[0].read_text(encoding="utf-8")
    assert "INVALID LINE HERE" in backup_content

def test_invalid_utf8_recreates(mock_env_path):
    # Invalid UTF-8 bytes
    mock_env_path.write_bytes(b'\x97\x98\x99')
    
    load_config()
    
    # File should be recreated with proper UTF-8 default content
    content = mock_env_path.read_text(encoding="utf-8")
    assert "DEFAULT_SEVERITY=" in content
    
    # Backup should exist
    backups = list(mock_env_path.parent.glob(".env.corrupted.*"))
    assert len(backups) == 1
    
    backup_content = backups[0].read_bytes()
    assert backup_content == b'\x97\x98\x99'

def test_normal_configuration_loads_successfully(mock_env_path):
    # Valid syntax
    mock_env_path.write_text("CUSTOM_VAR=value\n# Comment\n", encoding="utf-8")
    
    load_config()
    
    # File should remain unmodified
    content = mock_env_path.read_text(encoding="utf-8")
    assert "CUSTOM_VAR=value" in content
    assert "DEFAULT_SEVERITY" not in content
    
    # No backup
    backups = list(mock_env_path.parent.glob(".env.corrupted.*"))
    assert len(backups) == 0
