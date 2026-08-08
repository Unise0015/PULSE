import difflib
import logging
from typing import Any, Dict, List, Tuple

from pulse.core.config_schema import CONFIG_SCHEMA, ConfigOption

logger = logging.getLogger(__name__)

def validate_config(
    raw_config: Dict[str, str]
) -> Tuple[Dict[str, Any], List[str], Dict[str, str]]:
    """
    Validates a raw key-value dictionary against CONFIG_SCHEMA.
    Returns:
      - typed_config: Dict[str, Any] with typed, sanitized values
      - warnings: List[str] of repair & validation warnings
      - unknown_keys: Dict[str, str] mapping unknown_key -> suggested_match
    """
    typed_config: Dict[str, Any] = {}
    warnings: List[str] = []
    unknown_keys: Dict[str, str] = {}

    schema_keys = set(CONFIG_SCHEMA.keys())
    alias_map: Dict[str, str] = {}
    for k, opt in CONFIG_SCHEMA.items():
        for alias in opt.deprecated_aliases:
            alias_map[alias] = k

    # Process provided keys
    for raw_key, raw_val in raw_config.items():
        key = raw_key.strip()
        if not key:
            continue

        # Handle deprecated aliases
        if key in alias_map:
            target_key = alias_map[key]
            warnings.append(f"Deprecated setting '{key}' detected. Migrating to '{target_key}'.")
            key = target_key

        if key not in CONFIG_SCHEMA:
            # Detect unknown keys & fuzzy match suggestion
            matches = difflib.get_close_matches(key, schema_keys, n=1, cutoff=0.6)
            suggestion = matches[0] if matches else ""
            unknown_keys[key] = suggestion
            if suggestion:
                warnings.append(f"Unknown configuration key '{key}'. Did you mean '{suggestion}'?")
            else:
                warnings.append(f"Unknown configuration key '{key}'.")
            continue

        opt = CONFIG_SCHEMA[key]
        is_valid, err_msg = opt.validator(raw_val)
        if is_valid:
            try:
                typed_config[key] = opt.type_converter(raw_val)
            except Exception as e:
                warnings.append(
                    f"Type conversion error for '{key}' with value '{raw_val}': {e}. Restoring default '{opt.default}'."
                )
                typed_config[key] = opt.default
        else:
            warnings.append(
                f"Invalid value '{raw_val}' for configuration setting '{key}' ({err_msg}). Restoring default '{opt.default}'."
            )
            typed_config[key] = opt.default

    # Fill missing keys with schema defaults
    for k, opt in CONFIG_SCHEMA.items():
        if k not in typed_config:
            typed_config[k] = opt.default

    return typed_config, warnings, unknown_keys
