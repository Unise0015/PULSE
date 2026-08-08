import os
import json
import shutil
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pulse.config as config_module
from pulse import __version__
from pulse.core.config_schema import CONFIG_SCHEMA, ConfigOption, compute_schema_hash
from pulse.core.config_validator import validate_config

logger = logging.getLogger(__name__)

MAX_BACKUPS_RETAINED = 10

class ConfigService:
    """Centralized configuration service for PULSE Security Scanner."""

    _instance: Optional["ConfigService"] = None
    _cached_config: Dict[str, Any] = {}
    _is_initialized: bool = False

    @classmethod
    def get_instance(cls) -> "ConfigService":
        if cls._instance is None:
            cls._instance = ConfigService()
        return cls._instance

    def initialize(self) -> None:
        """Initializes configuration subsystem, handling migration, validation, and backups."""
        self.reload()
        self._is_initialized = True

    def reload(self) -> Dict[str, Any]:
        """Reloads configuration from .env file, applying migrations and validation."""
        env_path = config_module.get_env_file_path()
        raw_config = self._read_env_file(env_path)

        # Detect migration requirement
        schema_ver = raw_config.get("CONFIG_SCHEMA_VERSION", raw_config.get("CONFIG_VERSION", "1"))
        try:
            ver_num = int(schema_ver)
        except ValueError:
            ver_num = 1

        has_deprecated = "REPORT_KEEP_HISTORY" in raw_config

        if has_deprecated and env_path.exists():
            self._create_backup(env_path, version_tag=f"v{ver_num}")
            if "HISTORY_MAX_SCANS" not in raw_config:
                raw_config["HISTORY_MAX_SCANS"] = raw_config["REPORT_KEEP_HISTORY"]
            del raw_config["REPORT_KEEP_HISTORY"]
            raw_config["CONFIG_SCHEMA_VERSION"] = "2"

        raw_config["CONFIG_GENERATED_BY"] = __version__
        raw_config["CONFIG_SCHEMA_HASH"] = compute_schema_hash()

        typed_config, warnings, unknown_keys = validate_config(raw_config)
        self._cached_config = typed_config
        self._sync_to_os_environ(typed_config)

        if has_deprecated or not env_path.exists():
            self.save(typed_config, create_backup_first=False)

        for w in warnings:
            logger.info(f"Config: {w}")

        return dict(self._cached_config)

    def get(self, key: str, default: Any = None) -> Any:
        """Retrieves a typed setting value from in-memory cache."""
        if not self._is_initialized:
            self.reload()
        for k, opt in CONFIG_SCHEMA.items():
            if key in opt.deprecated_aliases:
                key = k
                break
        if key in self._cached_config:
            return self._cached_config[key]
        if key in CONFIG_SCHEMA:
            return CONFIG_SCHEMA[key].default
        return default

    def set(self, key: str, value: Any) -> Tuple[bool, str]:
        """Validates and updates a setting atomically."""
        alias_map = {}
        for k, opt in CONFIG_SCHEMA.items():
            for alias in opt.deprecated_aliases:
                alias_map[alias] = k

        if key in alias_map:
            key = alias_map[key]

        if key not in CONFIG_SCHEMA:
            return False, f"Unknown configuration key '{key}'"

        opt = CONFIG_SCHEMA[key]
        is_valid, err_msg = opt.validator(value)
        if not is_valid:
            return False, f"Validation failed for '{key}': {err_msg}"

        typed_val = opt.type_converter(value)
        new_config = dict(self._cached_config)
        new_config[key] = typed_val

        success, save_msg = self.save(new_config, create_backup_first=True)
        if success:
            self._cached_config[key] = typed_val
            os.environ[key] = str(typed_val)
            return True, f"Updated {key}={typed_val}"
        return False, save_msg

    def save(self, config_data: Dict[str, Any], create_backup_first: bool = True) -> Tuple[bool, str]:
        """Atomically saves configuration to .env file with file locking and rollback protection."""
        env_path = config_module.get_env_file_path()
        lock_path = env_path.parent / ".env.lock"

        if create_backup_first and env_path.exists():
            self._create_backup(env_path)

        tmp_path = env_path.parent / f".env.tmp_{os.getpid()}"

        try:
            # Format and write .env
            lines = self._format_env_lines(config_data)
            with open(tmp_path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")
                f.flush()
                os.fsync(f.fileno())

            # Atomic swap
            os.replace(tmp_path, env_path)

            # Post-write validation check
            test_read = self._read_env_file(env_path)
            _, test_warnings, _ = validate_config(test_read)
            if any("Invalid value" in w for w in test_warnings):
                self._rollback_latest_backup(env_path)
                return False, "Post-write validation failed. Configuration rolled back to backup."

            self.reload()
            return True, "Configuration saved successfully"
        except Exception as e:
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except OSError:
                    pass
            logger.error(f"Failed atomic config write: {e}")
            return False, f"Write error: {e}"

    def diff_config(self) -> Dict[str, Tuple[Any, Any]]:
        """Returns dictionary of customized settings differing from default schema: {key: (current, default)}."""
        diffs = {}
        for k, opt in CONFIG_SCHEMA.items():
            curr = self.get(k)
            if curr != opt.default:
                diffs[k] = (curr, opt.default)
        return diffs

    def reset(self) -> None:
        """Resets configuration to schema defaults."""
        env_path = config_module.get_env_file_path()
        if env_path.exists():
            self._create_backup(env_path, version_tag="reset")
        defaults = {k: opt.default for k, opt in CONFIG_SCHEMA.items()}
        self.save(defaults, create_backup_first=False)

    def export_config(self, export_path: Path, format: str = "json") -> Tuple[bool, str]:
        """Exports configuration to file in JSON or .env format with wrapper metadata."""
        try:
            export_path = Path(export_path)
            export_path.parent.mkdir(parents=True, exist_ok=True)

            if format.lower() == "json" or export_path.suffix.lower() == ".json":
                payload = {
                    "schema_version": self.get("CONFIG_SCHEMA_VERSION", 2),
                    "generated_by": f"PULSE {__version__}",
                    "generated_at": datetime.now().isoformat(),
                    "schema_hash": self.get("CONFIG_SCHEMA_HASH", ""),
                    "settings": {k: self.get(k) for k in CONFIG_SCHEMA.keys()}
                }
                with open(export_path, "w", encoding="utf-8") as f:
                    json.dump(payload, f, indent=2, ensure_ascii=False)
            else:
                lines = self._format_env_lines(self._cached_config)
                with open(export_path, "w", encoding="utf-8") as f:
                    f.write("\n".join(lines) + "\n")
            return True, f"Exported configuration to {export_path}"
        except Exception as e:
            return False, f"Export failed: {e}"

    def import_config(self, import_path: Path) -> Tuple[bool, str]:
        """Transactional import pipeline. Aborts with zero side effects on validation error."""
        try:
            path = Path(import_path)
            if not path.exists():
                return False, f"Import file '{path}' does not exist"

            raw_dict: Dict[str, str] = {}
            if path.suffix.lower() == ".json":
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                settings_map = data.get("settings", data)
                raw_dict = {str(k): str(v) for k, v in settings_map.items()}
            else:
                raw_dict = self._read_env_file(path)

            # Validate imported configuration candidate
            candidate_typed, warnings, _ = validate_config(raw_dict)
            invalid_warnings = [w for w in warnings if "Invalid value" in w]
            if invalid_warnings:
                return False, f"Import validation failed: {'; '.join(invalid_warnings)}. Original configuration untouched."

            # Perform backup and save
            env_path = config_module.get_env_file_path()
            if env_path.exists():
                self._create_backup(env_path, version_tag="pre-import")

            success, msg = self.save(candidate_typed, create_backup_first=False)
            if success:
                self.reload()
                return True, "Configuration imported successfully"
            return False, f"Import failed: {msg}"
        except Exception as e:
            return False, f"Import error: {e}"

    def generate_markdown_docs(self, output_path: Optional[Path] = None) -> str:
        """Generates markdown configuration documentation directly from CONFIG_SCHEMA."""
        categories: Dict[str, List[ConfigOption]] = {}
        for opt in CONFIG_SCHEMA.values():
            categories.setdefault(opt.category, []).append(opt)

        lines = [
            "# PULSE Configuration Reference",
            "",
            "This document is generated directly from `ConfigSchema`. Do not edit manually.",
            ""
        ]

        for cat, options in categories.items():
            lines.append(f"## {cat} Settings")
            lines.append("")
            lines.append("| Key | Default | Description |")
            lines.append("| --- | --- | --- |")
            for opt in options:
                def_val = f"`{opt.default}`" if opt.default != "" else "*empty*"
                lines.append(f"| `{opt.key}` | {def_val} | {opt.description} |")
            lines.append("")

        content = "\n".join(lines)
        if output_path:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(content)

        return content

    # Helper methods
    def _read_env_file(self, path: Path) -> Dict[str, str]:
        res: Dict[str, str] = {}
        if not path.exists():
            return res
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    res[k.strip()] = v.strip()
        except Exception as e:
            logger.warning(f"Error reading env file {path}: {e}")
        return res

    def _format_env_lines(self, config_data: Dict[str, Any]) -> List[str]:
        lines: List[str] = [f"# PULSE Configuration File (Schema v2)"]
        categories: Dict[str, List[str]] = {}

        for k in config_data.keys():
            if k in CONFIG_SCHEMA:
                cat = CONFIG_SCHEMA[k].category
                categories.setdefault(cat, []).append(k)

        for cat, keys in categories.items():
            lines.append("")
            lines.append(f"# --- {cat} ---")
            for k in keys:
                val = config_data[k]
                lines.append(f"{k}={val}")

        return lines

    def _create_backup(self, env_path: Path, version_tag: str = "v1") -> None:
        try:
            ts = datetime.now().strftime("%Y%m%d-%H%M%S")
            backup_name = f".env.backup.{ts}.{version_tag}"
            backup_path = env_path.parent / backup_name
            shutil.copy2(env_path, backup_path)
            self._prune_backups(env_path.parent)
        except Exception as e:
            logger.warning(f"Failed to create config backup: {e}")

    def _rollback_latest_backup(self, env_path: Path) -> None:
        backups = sorted(env_path.parent.glob(".env.backup.*"), key=lambda p: p.stat().st_mtime, reverse=True)
        if backups:
            try:
                shutil.copy2(backups[0], env_path)
                logger.info(f"Rolled back configuration to {backups[0].name}")
            except Exception as e:
                logger.error(f"Failed config rollback: {e}")

    def _prune_backups(self, parent_dir: Path) -> None:
        backups = sorted(parent_dir.glob(".env.backup.*"), key=lambda p: p.stat().st_mtime, reverse=True)
        if len(backups) > MAX_BACKUPS_RETAINED:
            for old_b in backups[MAX_BACKUPS_RETAINED:]:
                try:
                    old_b.unlink()
                except OSError:
                    pass

    def _sync_to_os_environ(self, config_data: Dict[str, Any]) -> None:
        for k, v in config_data.items():
            os.environ[k] = str(v)
