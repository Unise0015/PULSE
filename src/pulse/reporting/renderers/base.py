from abc import ABC, abstractmethod
from pulse.reporting.models import ReportModel

class BaseRenderer(ABC):
    """Abstract base renderer interface ensuring all report renderers behave consistently."""

    @abstractmethod
    def render(self, report: ReportModel) -> str:
        """Render the canonical ReportModel into string representation."""
        pass
