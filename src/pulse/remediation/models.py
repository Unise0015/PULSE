from dataclasses import dataclass, field
from typing import Optional, List
from enum import Enum
from datetime import datetime
from pulse.version_intelligence.models import (
    RecommendationMethod, RecommendationEvidence, UpgradeRecommendation,
    MigrationRisk, RecommendationConfidence
)

class RecommendationReasonCode(str, Enum):
    PATCH_FIX = "PATCH_FIX"
    MINOR_FIX = "MINOR_FIX"
    LTS_RECOMMENDED = "LTS_RECOMMENDED"
    LATEST_REQUIRED = "LATEST_REQUIRED"
    FIX_VERSION_UNKNOWN = "FIX_VERSION_UNKNOWN"
    MAJOR_UPGRADE_REQUIRED = "MAJOR_UPGRADE_REQUIRED"

__all__ = [
    "MigrationRisk",
    "RecommendationConfidence",
    "RecommendationReasonCode",
    "RecommendationMethod",
    "RecommendationEvidence",
    "UpgradeRecommendation",
]
