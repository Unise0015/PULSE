import os
import shutil
from pathlib import Path
from typing import Any

CONFIG_DIR_NAME = ".pulse"
LEGACY_CONFIG_DIR_NAME = ".cve-scanner"
ENV_FILE_NAME = ".env"

def get_config_dir() -> Path:
    """Get the path to the configuration directory, creating it if it doesn't exist."""
    home_dir = Path.home()
    config_dir = home_dir / CONFIG_DIR_NAME
    legacy_dir = home_dir / LEGACY_CONFIG_DIR_NAME
    
    if not config_dir.exists():
        if legacy_dir.exists():
            try:
                shutil.copytree(legacy_dir, config_dir)
            except Exception:
                config_dir.mkdir(parents=True, exist_ok=True)
        else:
            config_dir.mkdir(parents=True, exist_ok=True)
        
    return config_dir

def get_env_file_path() -> Path:
    """Get the path to the .env file."""
    return get_config_dir() / ENV_FILE_NAME

def _create_default_config(env_path: Path):
    from pulse.core.config_service import ConfigService
    ConfigService.get_instance().reset()

def _validate_env_file(env_path: Path) -> bool:
    try:
        if not env_path.exists():
            return True
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    return False
        return True
    except Exception:
        return False

from datetime import datetime

def load_config(console=None) -> None:
    """Load configuration using ConfigService, performing validation, corruption backup, and migration."""
    env_path = get_env_file_path()
    if env_path.exists() and not _validate_env_file(env_path):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"{ENV_FILE_NAME}.corrupted.{timestamp}"
        backup_path = env_path.parent / backup_name
        try:
            shutil.copy2(env_path, backup_path)
        except Exception:
            pass
        _create_default_config(env_path)
        return

    from pulse.core.config_service import ConfigService
    ConfigService.get_instance().initialize()

def get_setting(key: str, default: Any = "") -> str:
    """Retrieve a setting value via ConfigService."""
    from pulse.core.config_service import ConfigService
    val = ConfigService.get_instance().get(key, default)
    if val is None:
        return str(default) if default is not None else ""
    return str(val)

def set_setting(key: str, value: Any) -> None:
    """Set a setting value via ConfigService."""
    val_str = "" if value is None else str(value)
    os.environ[key] = val_str
    from pulse.core.config_service import ConfigService
    ConfigService.get_instance().set(key, value)

def remove_setting(key: str) -> None:
    """Remove a setting from environment and saved file."""
    from pulse.core.config_service import ConfigService
    cs = ConfigService.get_instance()
    cfg = dict(cs._cached_config)
    if key in cfg:
        del cfg[key]
        cs.save(cfg, create_backup_first=True)
