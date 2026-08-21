import hashlib
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from pulse import __version__

def _str_to_bool(val: Any) -> bool:
    if isinstance(val, bool):
        return val
    s = str(val).strip().lower()
    return s in ("true", "1", "yes", "on", "t")

def _str_to_int(val: Any) -> int:
    if isinstance(val, int):
        return val
    return int(str(val).strip())

def _str_to_str(val: Any) -> str:
    if val is None:
        return ""
    return str(val).strip()


@dataclass
class ConfigOption:
    key: str
    default: Any
    description: str
    category: str
    validator: Callable[[Any], Tuple[bool, str]]
    type_converter: Callable[[Any], Any] = _str_to_str
    deprecated_aliases: List[str] = field(default_factory=list)


# Validator helper generators
def _int_range(min_val: Optional[int] = None, max_val: Optional[int] = None):
    def _validate(val: Any) -> Tuple[bool, str]:
        try:
            v = _str_to_int(val)
            if min_val is not None and v < min_val:
                return False, f"Value {v} must be >= {min_val}"
            if max_val is not None and v > max_val:
                return False, f"Value {v} must be <= {max_val}"
            return True, "Valid"
        except (ValueError, TypeError):
            return False, f"Invalid integer value '{val}'"
    return _validate

def _choice(allowed_choices: Tuple[str, ...], case_sensitive: bool = False):
    def _validate(val: Any) -> Tuple[bool, str]:
        if val is None:
            return False, "Value cannot be None"
        v_str = str(val).strip()
        if not case_sensitive:
            choices_cmp = [c.lower() for c in allowed_choices]
            if v_str.lower() in choices_cmp:
                return True, "Valid"
        else:
            if v_str in allowed_choices:
                return True, "Valid"
        return False, f"Value '{v_str}' must be one of: {', '.join(allowed_choices)}"
    return _validate

def _always_valid(val: Any) -> Tuple[bool, str]:
    return True, "Valid"

def _bool_valid(val: Any) -> Tuple[bool, str]:
    if isinstance(val, bool):
        return True, "Valid"
    s = str(val).strip().lower()
    if s in ("true", "false", "1", "0", "yes", "no", "on", "off", "t", "f"):
        return True, "Valid"
    return False, f"Invalid boolean value '{val}'"


# Configuration Schema Single Source of Truth
CONFIG_SCHEMA: Dict[str, ConfigOption] = {
    # System Metadata
    "CONFIG_SCHEMA_VERSION": ConfigOption(
        key="CONFIG_SCHEMA_VERSION",
        default=2,
        description="Configuration schema version for migrations",
        category="General",
        validator=_int_range(min_val=1),
        type_converter=_str_to_int
    ),
    "CONFIG_GENERATED_BY": ConfigOption(
        key="CONFIG_GENERATED_BY",
        default=__version__,
        description="PULSE scanner release version that generated configuration",
        category="General",
        validator=_always_valid,
        type_converter=_str_to_str
    ),
    "CONFIG_SCHEMA_HASH": ConfigOption(
        key="CONFIG_SCHEMA_HASH",
        default="",
        description="Checksum hash of configuration schema definition",
        category="General",
        validator=_always_valid,
        type_converter=_str_to_str
    ),

    # General
    "DEFAULT_SEVERITY": ConfigOption(
        key="DEFAULT_SEVERITY",
        default="ALL",
        description="Default severity threshold for scan filtering",
        category="General",
        validator=_choice(("ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")),
        type_converter=lambda v: str(v).strip().upper()
    ),
    "DEFAULT_OUTPUT": ConfigOption(
        key="DEFAULT_OUTPUT",
        default="table",
        description="Default CLI output format",
        category="General",
        validator=_choice(("table", "json", "html", "markdown", "sarif", "csv")),
        type_converter=lambda v: str(v).strip().lower()
    ),
    "OFFLINE_MODE": ConfigOption(
        key="OFFLINE_MODE",
        default=False,
        description="Disable remote network requests and rely on local cache",
        category="General",
        validator=_bool_valid,
        type_converter=_str_to_bool
    ),

    # Scanning
    "CACHE_DURATION": ConfigOption(
        key="CACHE_DURATION",
        default=24,
        description="Vulnerability intelligence cache TTL in hours",
        category="Scanning",
        validator=_int_range(min_val=1),
        type_converter=_str_to_int
    ),

    # History
    "HISTORY_MAX_SCANS": ConfigOption(
        key="HISTORY_MAX_SCANS",
        default=100,
        description="Maximum scan history entries to retain",
        category="History",
        validator=_int_range(min_val=1),
        type_converter=_str_to_int,
        deprecated_aliases=["REPORT_KEEP_HISTORY"]
    ),
    "HISTORY_RETENTION_DAYS": ConfigOption(
        key="HISTORY_RETENTION_DAYS",
        default=90,
        description="Retention period for historical scan posture records in days",
        category="History",
        validator=_int_range(min_val=1),
        type_converter=_str_to_int
    ),

    # Reporting
    "REPORT_DEFAULT_LOCATION": ConfigOption(
        key="REPORT_DEFAULT_LOCATION",
        default="documents",
        description="Default storage location strategy for reports (documents, pulse, pwd, custom)",
        category="Reporting",
        validator=_choice(("documents", "pulse", "pwd", "custom")),
        type_converter=lambda v: str(v).strip().lower()
    ),
    "REPORT_DEFAULT_FORMAT": ConfigOption(
        key="REPORT_DEFAULT_FORMAT",
        default="HTML",
        description="Default format for report export workflows",
        category="Reporting",
        validator=_choice(("HTML", "JSON", "Markdown", "SARIF", "CSV")),
        type_converter=lambda v: str(v).strip().upper()
    ),
    "REPORT_CUSTOM_DIR": ConfigOption(
        key="REPORT_CUSTOM_DIR",
        default="",
        description="Custom directory for exporting reports",
        category="Reporting",
        validator=_always_valid,
        type_converter=_str_to_str
    ),
    "REPORT_AUTO_OPEN_HTML": ConfigOption(
        key="REPORT_AUTO_OPEN_HTML",
        default=False,
        description="Automatically open HTML report in web browser after export",
        category="Reporting",
        validator=_bool_valid,
        type_converter=_str_to_bool
    ),
    "REPORT_GENERATE_AUTO": ConfigOption(
        key="REPORT_GENERATE_AUTO",
        default=False,
        description="Automatically generate report upon scan completion",
        category="Reporting",
        validator=_bool_valid,
        type_converter=_str_to_bool
    ),
    "REPORT_THEME": ConfigOption(
        key="REPORT_THEME",
        default="light",
        description="Color theme for HTML report dashboard",
        category="Reporting",
        validator=_choice(("light", "dark")),
        type_converter=lambda v: str(v).strip().lower()
    ),

    # API Keys
    "NVD_API_KEY": ConfigOption(
        key="NVD_API_KEY",
        default="",
        description="National Vulnerability Database API key",
        category="API Keys",
        validator=_always_valid,
        type_converter=_str_to_str
    ),

    # Logging
    "LOG_LEVEL": ConfigOption(
        key="LOG_LEVEL",
        default="INFO",
        description="Logging level threshold",
        category="Logging",
        validator=_choice(("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")),
        type_converter=lambda v: str(v).strip().upper()
    ),
    "LOG_RETENTION_DAYS": ConfigOption(
        key="LOG_RETENTION_DAYS",
        default=30,
        description="Daily log file retention period",
        category="Logging",
        validator=_int_range(min_val=1),
        type_converter=_str_to_int
    ),
    "DEBUG_MODE": ConfigOption(
        key="DEBUG_MODE",
        default=False,
        description="Enable debug diagnostics and stack traces",
        category="Logging",
        validator=_bool_valid,
        type_converter=_str_to_bool
    ),
    "VERBOSE_MODE": ConfigOption(
        key="VERBOSE_MODE",
        default=False,
        description="Enable verbose CLI output by default",
        category="Logging",
        validator=_bool_valid,
        type_converter=_str_to_bool
    ),

    # Networking
    "HTTP_TIMEOUT": ConfigOption(
        key="HTTP_TIMEOUT",
        default=10,
        description="HTTP client request timeout in seconds",
        category="Networking",
        validator=_int_range(min_val=1),
        type_converter=_str_to_int
    ),
    "MAX_REDIRECTS": ConfigOption(
        key="MAX_REDIRECTS",
        default=5,
        description="Maximum HTTP redirect follow count",
        category="Networking",
        validator=_int_range(min_val=0),
        type_converter=_str_to_int
    ),
    "MAX_CONCURRENT_REQUESTS": ConfigOption(
        key="MAX_CONCURRENT_REQUESTS",
        default=8,
        description="Maximum concurrent HTTP connections",
        category="Networking",
        validator=_int_range(min_val=1),
        type_converter=_str_to_int
    ),

    # Website
    "EXTERNAL_ONLY": ConfigOption(
        key="EXTERNAL_ONLY",
        default=False,
        description="Reject website scans against localhost and private IP ranges",
        category="Website",
        validator=_bool_valid,
        type_converter=_str_to_bool
    ),

    # CLI
    "COLOR_OUTPUT": ConfigOption(
        key="COLOR_OUTPUT",
        default=True,
        description="Enable colored CLI terminal output",
        category="CLI",
        validator=_bool_valid,
        type_converter=_str_to_bool
    ),
    "UNICODE_OUTPUT": ConfigOption(
        key="UNICODE_OUTPUT",
        default=True,
        description="Enable unicode glyphs in CLI output",
        category="CLI",
        validator=_bool_valid,
        type_converter=_str_to_bool
    ),
    "PROGRESS_BARS": ConfigOption(
        key="PROGRESS_BARS",
        default=True,
        description="Enable animated progress bars during scans",
        category="CLI",
        validator=_bool_valid,
        type_converter=_str_to_bool
    ),
}

def compute_schema_hash() -> str:
    """Computes SHA256 checksum hash of the schema definition."""
    content = ""
    for k in sorted(CONFIG_SCHEMA.keys()):
        opt = CONFIG_SCHEMA[k]
        content += f"{opt.key}:{opt.default}:{opt.category};"
    return hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]

# Update schema hash default dynamically
CONFIG_SCHEMA["CONFIG_SCHEMA_HASH"].default = compute_schema_hash()
