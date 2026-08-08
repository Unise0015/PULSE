from pulse.core.config_validator import validate_config

def test_validate_config_valid_input():
    raw = {
        "CACHE_DURATION": "48",
        "DEFAULT_OUTPUT": "json",
        "OFFLINE_MODE": "true"
    }
    typed, warnings, unknown = validate_config(raw)
    assert typed["CACHE_DURATION"] == 48
    assert typed["DEFAULT_OUTPUT"] == "json"
    assert typed["OFFLINE_MODE"] is True
    assert len(unknown) == 0


def test_validate_config_invalid_values_fallback():
    raw = {
        "CACHE_DURATION": "-10",
        "DEFAULT_OUTPUT": "invalid_format",
        "REPORT_THEME": "purple"
    }
    typed, warnings, _ = validate_config(raw)
    assert typed["CACHE_DURATION"] == 24  # Restored default
    assert typed["DEFAULT_OUTPUT"] == "table"
    assert typed["REPORT_THEME"] == "light"
    assert any("Invalid value" in w for w in warnings)


def test_validate_config_unknown_key_fuzzy_matching():
    raw = {
        "CACHE_TIME": "10",
        "HTTP_TIMOUT": "15"
    }
    typed, warnings, unknown = validate_config(raw)
    assert "CACHE_TIME" in unknown
    assert unknown["CACHE_TIME"] == "CACHE_DURATION"
    assert "HTTP_TIMOUT" in unknown
    assert unknown["HTTP_TIMOUT"] == "HTTP_TIMEOUT"
    assert any("Did you mean 'CACHE_DURATION'" in w for w in warnings)
