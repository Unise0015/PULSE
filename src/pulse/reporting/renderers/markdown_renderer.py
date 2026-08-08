from pathlib import Path
from jinja2 import Environment, FileSystemLoader
from pulse.reporting.models import ReportModel
from pulse.reporting.renderers.base import BaseRenderer

class MarkdownRenderer(BaseRenderer):
    """GitHub-flavored Markdown renderer consuming the canonical ReportModel."""

    def __init__(self, template_dir: Optional[Path] = None):
        if template_dir is None:
            template_dir = Path(__file__).parent.parent / "templates"
        self.env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=False
        )
        self.env.filters["datetime_fmt"] = self._datetime_fmt

    @staticmethod
    def _datetime_fmt(val) -> str:
        if not val:
            return "N/A"
        if hasattr(val, "strftime"):
            return val.strftime("%B %d %Y")
        return str(val)

    def render(self, report: ReportModel) -> str:
        template = self.env.get_template("report.md.j2")
        return template.render(report=report)
