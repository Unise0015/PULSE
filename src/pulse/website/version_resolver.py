from enum import Enum
from typing import Optional, Tuple
import re

class VersionResolutionStatus(str, Enum):
    VERIFIED = "verified"
    ESTIMATED = "estimated"
    UNKNOWN = "unknown"
    UNAVAILABLE = "unavailable"

def resolve_version(tech_key: str, raw_version: Optional[str], detection_confidence: int = 100) -> Tuple[Optional[str], VersionResolutionStatus]:
    """Normalize a raw version string and assign a VersionResolutionStatus.
    
    Args:
        tech_key: Normalized catalog key
        raw_version: Raw version string detected from fingerprints
        detection_confidence: Confidence score of detection (0-100)
        
    Returns:
        Tuple[normalized_version_string, VersionResolutionStatus]
    """
    if not raw_version:
        return None, VersionResolutionStatus.UNKNOWN
        
    cleaned_version = raw_version.strip()
    if not cleaned_version:
        return None, VersionResolutionStatus.UNKNOWN
        
    lower_val = cleaned_version.lower()
    
    # Check if version is obfuscated/unavailable
    if lower_val in ("obfuscated", "hidden", "private", "unavailable", "unknown", "none", "null", "undefined"):
        return None, VersionResolutionStatus.UNAVAILABLE
        
    # Strip leading 'v' or 'v.'
    if cleaned_version.startswith("v."):
        cleaned_version = cleaned_version[2:]
    elif cleaned_version.startswith("v"):
        cleaned_version = cleaned_version[1:]
        
    # Clean trailing text/spaces (e.g. "3.5.1-dist" -> "3.5.1-dist")
    match = re.match(r"^([0-9a-zA-Z\.\-\+]+)", cleaned_version)
    if match:
        cleaned_version = match.group(1)
        
    # Verify semantic match structure
    # Standard semver-like format: e.g. 1.2.3 or 1.2 or 6.1.1
    is_exact = re.match(r"^\d+(\.\d+)*$", cleaned_version) is not None
    
    if not is_exact or "x" in lower_val or "*" in lower_val or detection_confidence < 70:
        return cleaned_version, VersionResolutionStatus.ESTIMATED
        
    return cleaned_version, VersionResolutionStatus.VERIFIED
