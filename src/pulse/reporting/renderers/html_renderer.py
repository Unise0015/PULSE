from pathlib import Path
from typing import Optional
from jinja2 import Environment, FileSystemLoader
from pulse.reporting.models import ReportModel
from pulse.reporting.renderers.base import BaseRenderer

class HTMLRenderer(BaseRenderer):
    """Commercial-grade interactive HTML dashboard renderer."""

    def __init__(self, template_dir: Optional[Path] = None):
        if template_dir is None:
            template_dir = Path(__file__).parent.parent / "templates"
        self.env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=False
        )
        self.env.filters["datetime_fmt"] = self._datetime_fmt
        self.env.filters["duration_fmt"] = self._duration_fmt
        self.env.filters["posture_rating"] = self._posture_rating
        self.env.filters["posture_stars"] = self._posture_stars

    def render(self, report: ReportModel) -> str:
        template = self.env.get_template("base.html.j2")
        return template.render(report=report)

    @staticmethod
    def _datetime_fmt(val) -> str:
        if not val:
            return "N/A"
        if hasattr(val, "strftime"):
            return val.strftime("%d %b %Y %H:%M UTC")
        return str(val)

    @staticmethod
    def _duration_fmt(val) -> str:
        if not val:
            return "0s"
        if hasattr(val, "total_seconds"):
            secs = val.total_seconds()
            return f"{secs:.1f}s" if secs < 60 else f"{int(secs//60)}m {int(secs%60)}s"
        return str(val)

    @staticmethod
    def _posture_rating(score: int) -> str:
        if score >= 80:
            return "Critical Risk"
        elif score >= 60:
            return "High Risk"
        elif score >= 40:
            return "Moderate Risk"
        elif score >= 20:
            return "Low Risk"
        return "Minimal Risk"

    @staticmethod
    def _posture_stars(score: int) -> str:
        if score >= 80:
            return "★☆☆☆☆"
        elif score >= 60:
            return "★★☆☆☆"
        elif score >= 40:
            return "★★★☆☆"
        elif score >= 20:
            return "★★★★☆"
        return "★★★★★"
