"""
Backward-compatible facade for PULSE Declarative Web Technology Detection.
Delegates directly to pulse.website.declarative.engine.DeclarativeTechnologyEngine.
"""

from pathlib import Path
from typing import Dict, List, Optional
from pulse.domain.models import TechnologyFingerprint
from pulse.website.declarative.engine import DeclarativeTechnologyEngine as BaseEngine


class DeclarativeSignatureEngine(BaseEngine):
    """Facade class maintaining backward compatibility for DeclarativeSignatureEngine."""
    pass
