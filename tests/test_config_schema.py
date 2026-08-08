from pulse.core.config_schema import CONFIG_SCHEMA, ConfigOption, compute_schema_hash

def test_config_schema_single_source_of_truth():
    assert "CONFIG_SCHEMA_VERSION" in CONFIG_SCHEMA
    assert "DEFAULT_SEVERITY" in CONFIG_SCHEMA
    assert "CACHE_DURATION" in CONFIG_SCHEMA
    assert "HISTORY_MAX_SCANS" in CONFIG_SCHEMA
    assert "REPORT_THEME" in CONFIG_SCHEMA

    opt = CONFIG_SCHEMA["CACHE_DURATION"]
    assert isinstance(opt, ConfigOption)
    assert opt.default == 24
    assert opt.category == "Scanning"
    
    # Check compute_schema_hash
    hash_val = compute_schema_hash()
    assert isinstance(hash_val, str)
    assert len(hash_val) == 16
