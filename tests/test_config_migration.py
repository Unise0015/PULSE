import shutil
import tempfile
from pathlib import Path
from unittest.mock import patch

from pulse.core.config_service import ConfigService

def test_config_v1_to_v2_migration():
    temp_dir = tempfile.mkdtemp()
    try:
        ConfigService._instance = None
        env_file = Path(temp_dir) / ".env"
        # Write v1 legacy configuration file
        v1_content = (
            "DEFAULT_SEVERITY=high\n"
            "REPORT_KEEP_HISTORY=50\n"
            "CACHE_DURATION=36\n"
        )
        env_file.write_text(v1_content, encoding="utf-8")

        with patch("pulse.config.get_config_dir", return_value=Path(temp_dir)):
            cs = ConfigService.get_instance()
            cs.reload()

            assert cs.get("CONFIG_SCHEMA_VERSION") == 2
            assert cs.get("HISTORY_MAX_SCANS") == 50
            assert cs.get("CACHE_DURATION") == 36

            # Verify backup created
            backups = list(Path(temp_dir).glob(".env.backup.*"))
            assert len(backups) >= 1

            # Verify REPORT_KEEP_HISTORY removed from active file
            file_content = env_file.read_text(encoding="utf-8")
            assert "REPORT_KEEP_HISTORY" not in file_content
            assert "CONFIG_SCHEMA_VERSION=2" in file_content
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
