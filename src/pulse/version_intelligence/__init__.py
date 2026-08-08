"""PULSE Version Intelligence & Recommendation Subsystem."""

from pulse.version_intelligence.models import (
    UpgradeRecommendation,
    RecommendationStrategy,
    RecommendationConfidence,
    MigrationRisk,
    PackageManager,
    PackageManagerCommand,
    VerificationSource
)
from pulse.version_intelligence.command_generator import generate_package_manager_commands
from pulse.version_intelligence.recommendation_engine import analyze_upgrade_recommendation

__all__ = [
    "UpgradeRecommendation",
    "RecommendationStrategy",
    "RecommendationConfidence",
    "MigrationRisk",
    "PackageManager",
    "PackageManagerCommand",
    "VerificationSource",
    "generate_package_manager_commands",
    "analyze_upgrade_recommendation",
]
