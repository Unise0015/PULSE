import os
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
from pulse.config import get_config_dir
from pulse.domain.models import ScanResult
from pulse.reporting.context import ReportContext
from pulse.reporting.builder import ReportBuilder
from pulse.reporting.renderers import (
    HTMLRenderer, MarkdownRenderer, JSONRenderer, SARIFRenderer
)

class ReportService:
    """Central orchestrator for PULSE report generation, storage, and retrieval."""

    @staticmethod
    def get_reports_dir() -> Path:
        """Returns the base directory for report storage based on user configuration settings."""
        from pulse.reporting.path_resolver import ReportPathResolver
        return ReportPathResolver.get_configured_directory()

    @classmethod
    def generate_reports(
        cls,
        context: ReportContext,
        formats: Optional[List[str]] = None,
        custom_output_dir: Optional[Path] = None
    ) -> Dict[str, Path]:
        """Generates requested report formats from ReportContext and saves them under scan_<scan_id>/."""
        if formats is None:
            formats = ["html", "json", "markdown", "sarif"]

        # Build canonical ReportModel
        report_model = ReportBuilder.build(context)

        # Target directory: scan_<scan_id>/
        if custom_output_dir:
            scan_dir = custom_output_dir
        else:
            scan_dir = cls.get_reports_dir() / f"scan_{context.scan_id}"
        scan_dir.mkdir(parents=True, exist_ok=True)

        timestamp_dt = datetime.now()
        timestamp_str = timestamp_dt.strftime("%Y%m%d_%H%M%S")

        from pulse.reporting.path_resolver import ReportPathResolver

        renderers = {
            "html": (HTMLRenderer(), f"report_{timestamp_str}.html"),
            "json": (JSONRenderer(), f"report_{timestamp_str}.json"),
            "markdown": (MarkdownRenderer(), f"report_{timestamp_str}.md"),
            "md": (MarkdownRenderer(), f"report_{timestamp_str}.md"),
            "sarif": (SARIFRenderer(), f"report_{timestamp_str}.sarif.json")
        }

        generated_files: Dict[str, Path] = {}

        for fmt in formats:
            fmt_lower = fmt.lower()
            if fmt_lower in renderers:
                renderer, filename = renderers[fmt_lower]
                content = renderer.render(report_model)
                out_path = ReportPathResolver.resolve(
                    filename_or_base=filename,
                    configured_directory=scan_dir,
                    timestamp=timestamp_dt
                )
                with open(out_path, "w", encoding="utf-8") as f:
                    f.write(content)
                generated_files[fmt_lower] = out_path

                try:
                    from pulse.history import HistoryService
                    HistoryService().register_report_artifact(context.scan_id, fmt_lower, str(out_path.resolve()))
                except Exception:
                    pass

        # Maintain keep_report_history limit
        cls._cleanup_old_reports()

        return generated_files

    @classmethod
    def _cleanup_old_reports(cls) -> None:
        """Enforces HISTORY_MAX_SCANS / REPORT_KEEP_HISTORY limit by pruning oldest scan folders."""
        from pulse.config import get_setting
        import shutil
        try:
            raw_val = get_setting("HISTORY_MAX_SCANS", get_setting("REPORT_KEEP_HISTORY", "100"))
            max_keep = int(raw_val)
        except (ValueError, TypeError):
            max_keep = 100

        reports_dir = cls.get_reports_dir()
        if not reports_dir.exists():
            return

        scan_dirs = sorted(
            [d for d in reports_dir.iterdir() if d.is_dir() and d.name.startswith("scan_")],
            key=lambda d: d.stat().st_mtime
        )

        if len(scan_dirs) > max_keep:
            to_remove = scan_dirs[:len(scan_dirs) - max_keep]
            for folder in to_remove:
                try:
                    shutil.rmtree(folder, ignore_errors=True)
                except Exception:
                    pass

    @classmethod
    def open_report(cls, path: Path) -> bool:
        """Opens a report file using the system default handler (browser)."""
        if not path or not path.exists():
            return False
        try:
            webbrowser.open(path.as_uri())
            return True
        except Exception:
            return False

    @classmethod
    def get_last_report(cls, history_service=None) -> Optional[Dict[str, Any]]:
        """Retrieves details of the most recent scan report from authoritative report artifacts."""
        if history_service is None:
            from pulse.history import HistoryService
            history_service = HistoryService()

        artifact = history_service.get_latest_report_artifact("html")
        runs = history_service.get_scan_runs()
        latest_run = runs[0] if runs else {}

        if artifact:
            html_path = Path(artifact["path"])
            is_missing = not html_path.exists()
            return {
                "scan_id": artifact["scan_id"],
                "scan_dir": html_path.parent,
                "html_path": html_path,
                "missing": is_missing,
                "run_info": latest_run
            }

        if not runs:
            return None

        scan_id = str(latest_run.get("id", "latest"))
        saved_dir = latest_run.get("report_dir")
        scan_dir = Path(saved_dir) if saved_dir else cls.get_reports_dir()

        html_files = sorted(list(scan_dir.glob("*.html")), key=lambda p: p.stat().st_mtime, reverse=True) if scan_dir.exists() else []
        html_path = html_files[0] if html_files else (scan_dir / f"report_{scan_id}.html")

        return {
            "scan_id": scan_id,
            "scan_dir": scan_dir,
            "html_path": html_path,
            "missing": not html_path.exists(),
            "run_info": latest_run
        }

    @classmethod
    def create_scan_report(
        cls,
        scan_result: ScanResult,
        posture_delta: Optional[Any] = None,
        advisor: Optional[Any] = None,
        formats: Optional[List[str]] = None
    ) -> Dict[str, Path]:
        """Saves scan_result to HistoryService, builds ReportContext, generates reports, and records report_dir."""
        import sqlite3
        from pulse.config import get_setting
        from pulse.history import HistoryService

        history = HistoryService()
        scan_id_num = history.save_scan(scan_result)
        scan_id_str = f"{scan_id_num:06d}" if isinstance(scan_id_num, int) else str(scan_id_num)

        # Check if automatic report generation is disabled (default: False)
        auto_gen = get_setting("REPORT_GENERATE_AUTO", "false").lower() in ("true", "1", "yes")
        if not auto_gen and formats is None:
            return {}

        context = ReportContext(
            scan_result=scan_result,
            scan_id=scan_id_str,
            posture_delta=posture_delta,
            advisor=advisor
        )

        if formats is None:
            default_fmt = get_setting("REPORT_DEFAULT_FORMAT", "html").lower()
            if default_fmt == "all":
                fmt_list = ["html", "json", "markdown", "sarif"]
            else:
                fmt_list = list(set([default_fmt, "html"]))
        else:
            fmt_list = formats

        generated = cls.generate_reports(context, formats=fmt_list)

        if "html" in generated:
            scan_dir = generated["html"].parent
            with sqlite3.connect(history.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE scan_runs SET report_dir = ? WHERE id = ?", (str(scan_dir), scan_id_num))
                conn.commit()

            # Check if auto_open_html is enabled (default: False)
            auto_open = get_setting("REPORT_AUTO_OPEN_HTML", "false").lower() in ("true", "1", "yes")
            if auto_open and formats is None:
                cls.open_report(generated["html"])

        return generated
