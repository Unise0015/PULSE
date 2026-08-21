from enum import Enum
from typing import Optional
from pulse.domain.models import ScanResult

class SummaryMode(Enum):
    COMPACT = "compact"
    NORMAL = "normal"
    VERBOSE = "verbose"

class AppState:
    """Global application state."""
    LAST_SCAN: Optional[ScanResult] = None
    OFFLINE_MODE: bool = False
    VERBOSE_MODE: bool = False
    DEBUG_MODE: bool = False
    SHOW_ATTACK_PATHS: bool = False
    INCLUDE_HOST: bool = False
    SUMMARY_MODE: SummaryMode = SummaryMode.NORMAL
