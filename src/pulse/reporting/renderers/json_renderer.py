import json
import dataclasses
from datetime import datetime, timedelta
from enum import Enum
from pulse.reporting.models import ReportModel
from pulse.reporting.renderers.base import BaseRenderer

class ReportJSONEncoder(json.JSONEncoder):
    """Custom JSON encoder for ReportModel components (Enums, dataclasses, datetimes, timedeltas)."""
    def default(self, o):
        if isinstance(o, Enum):
            return o.value
        if dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)
        if isinstance(o, datetime):
            return o.isoformat()
        if isinstance(o, timedelta):
            return o.total_seconds()
        return super().default(o)

class JSONRenderer(BaseRenderer):
    """Canonical JSON renderer serializing the complete ReportModel API contract."""

    def render(self, report: ReportModel) -> str:
        data = dataclasses.asdict(report)
        return json.dumps(data, indent=2, ensure_ascii=False, cls=ReportJSONEncoder)
