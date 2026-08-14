from dataclasses import dataclass
from typing import Optional

@dataclass
class RegistryValidationResult:
    package_exists: bool
    version_exists: bool
    latest_available_version: Optional[str]
    network_error: bool
    http_status: Optional[int]
