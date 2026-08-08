"""
Centralized Report Path Resolver for PULSE CLI.
Enforces single source of truth for all report exports across formats.
"""

import os
from pathlib import Path
from datetime import datetime
from typing import Optional, Union


class ReportPathResolver:
    """Centralized resolver for report export paths across all exporters and workflows."""

    @staticmethod
    def default_directory() -> Path:
        """Returns the canonical OS Documents folder (~/Documents/PULSE Reports/)."""
        try:
            docs_dir = Path.home() / "Documents"
            if not docs_dir.exists():
                try:
                    docs_dir.mkdir(parents=True, exist_ok=True)
                except Exception:
                    docs_dir = Path.home()
        except Exception:
            docs_dir = Path.home()

        target = docs_dir / "PULSE Reports"
        target.mkdir(parents=True, exist_ok=True)
        return target

    @classmethod
    def get_configured_directory(cls) -> Path:
        """Resolves configured directory from settings (REPORT_CUSTOM_DIR or REPORT_DEFAULT_LOCATION)."""
        from pulse.config import get_setting
        loc = get_setting("REPORT_DEFAULT_LOCATION", "documents").lower()
        if loc == "pwd":
            target = Path.cwd() / "pulse-reports"
        elif loc == "custom":
            custom_path = get_setting("REPORT_CUSTOM_DIR", "").strip()
            if custom_path:
                target = Path(custom_path)
            else:
                target = cls.default_directory()
        else:
            target = cls.default_directory()

        target = Path(os.path.expanduser(str(target)))
        target.mkdir(parents=True, exist_ok=True)
        return target

    @classmethod
    def resolve(
        cls,
        filename_or_base: str = "report",
        explicit_path: Optional[Union[str, Path]] = None,
        configured_directory: Optional[Union[str, Path]] = None,
        timestamp: Optional[datetime] = None,
        extension: Optional[str] = None
    ) -> Path:
        """
        Resolves final export Path following strict precedence:
          1. explicit_path (if provided)
          2. configured_directory (if provided)
          3. Saved configuration setting (REPORT_CUSTOM_DIR / REPORT_DEFAULT_LOCATION)
          4. Default directory (~/Documents/PULSE Reports/)

        Also ensures timestamp (date and time) is appended to filenames when appropriate.
        """
        if timestamp is None:
            timestamp = datetime.now()

        timestamp_str = timestamp.strftime("%Y%m%d_%H%M%S")

        # Priority 1: Explicit Path
        if explicit_path:
            raw_str = str(explicit_path).strip()
            p = Path(os.path.expanduser(raw_str))

            if p.is_dir() or raw_str.endswith(("\\", "/")):
                p.mkdir(parents=True, exist_ok=True)
                base = filename_or_base or "report"
                fname = cls._format_filename(base, timestamp_str, extension)
                target_file = p / fname
            else:
                p.parent.mkdir(parents=True, exist_ok=True)
                target_file = p

            target_file.parent.mkdir(parents=True, exist_ok=True)
            return target_file

        # Priority 2 & 3: Configured directory parameter or settings lookup
        if configured_directory and str(configured_directory).strip():
            target_dir = Path(os.path.expanduser(str(configured_directory).strip()))
        else:
            target_dir = cls.get_configured_directory()

        target_dir.mkdir(parents=True, exist_ok=True)
        fname = cls._format_filename(filename_or_base, timestamp_str, extension)
        target_file = target_dir / fname
        target_file.parent.mkdir(parents=True, exist_ok=True)
        return target_file

    @staticmethod
    def _format_filename(base: str, timestamp_str: str, extension: Optional[str] = None) -> str:
        """Formats base filename with timestamp if not already timestamped."""
        path_obj = Path(base)
        ext = extension or path_obj.suffix
        stem = path_obj.stem if path_obj.suffix else base

        if not ext:
            ext = ".html"
        if not ext.startswith("."):
            ext = f".{ext}"

        if timestamp_str in stem:
            return f"{stem}{ext}"
        else:
            return f"{stem}_{timestamp_str}{ext}"
