import json
import shutil
import tempfile
from pathlib import Path
from unittest.mock import patch

from pulse.core.config_service import ConfigService

def test_config_service_reload_and_get():
    temp_dir = tempfile.mkdtemp()
    try:
        ConfigService._instance = None
        with patch("pulse.config.get_config_dir", return_value=Path(temp_dir)):
            with patch.dict("os.environ", {"DEFAULT_OUTPUT": "table"}):
                cs = ConfigService.get_instance()
                cs.reload()

                assert cs.get("CACHE_DURATION") == 24
                assert cs.get("DEFAULT_OUTPUT") == "table"

                success, msg = cs.set("CACHE_DURATION", 48)
                assert success is True
                assert cs.get("CACHE_DURATION") == 48
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_config_service_diff():
    temp_dir = tempfile.mkdtemp()
    try:
        ConfigService._instance = None
        with patch("pulse.config.get_config_dir", return_value=Path(temp_dir)):
            cs = ConfigService.get_instance()
            cs.reload()

            diffs_before = cs.diff_config()
            assert "CACHE_DURATION" not in diffs_before

            cs.set("CACHE_DURATION", 48)
            diffs_after = cs.diff_config()
            assert "CACHE_DURATION" in diffs_after
            assert diffs_after["CACHE_DURATION"] == (48, 24)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_config_service_export_import_transactional():
    temp_dir = tempfile.mkdtemp()
    try:
        ConfigService._instance = None
        with patch("pulse.config.get_config_dir", return_value=Path(temp_dir)):
            cs = ConfigService.get_instance()
            cs.reload()

            cs.set("CACHE_DURATION", 72)
            export_file = Path(temp_dir) / "export_cfg.json"

            success, msg = cs.export_config(export_file, format="json")
            assert success is True
            assert export_file.exists()

            # Corrupt export file for transactional test
            corrupt_file = Path(temp_dir) / "corrupt_cfg.json"
            corrupt_payload = {
                "settings": {
                    "CACHE_DURATION": -10,  # Invalid!
                    "DEFAULT_OUTPUT": "invalid"
                }
            }
            corrupt_file.write_text(json.dumps(corrupt_payload), encoding="utf-8")

            success, msg = cs.import_config(corrupt_file)
            assert success is False
            assert "validation failed" in msg.lower()
            # Verify active config remains untouched (72)
            assert cs.get("CACHE_DURATION") == 72
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
