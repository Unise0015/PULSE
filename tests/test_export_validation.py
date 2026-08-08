import pytest
from pulse.export_validator import ExportValidator
import json

def test_validate_json_export():
    valid = json.dumps({"findings": [], "summary": {}})
    invalid_no_findings = json.dumps({"summary": {}})
    invalid_type = json.dumps({"findings": "not_a_list", "summary": {}})
    
    assert ExportValidator.validate_json_export(valid) is True
    assert ExportValidator.validate_json_export(invalid_no_findings) is False
    assert ExportValidator.validate_json_export(invalid_type) is False
    assert ExportValidator.validate_json_export("not json") is False

def test_validate_cyclonedx_export():
    valid = json.dumps({
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "components": [],
        "vulnerabilities": [],
        "dependencies": []
    })
    invalid_format = json.dumps({
        "bomFormat": "Other",
        "specVersion": "1.4",
        "components": [],
        "vulnerabilities": [],
        "dependencies": []
    })
    missing_keys = json.dumps({
        "bomFormat": "CycloneDX",
        "components": []
    })
    
    assert ExportValidator.validate_cyclonedx_export(valid) is True
    assert ExportValidator.validate_cyclonedx_export(invalid_format) is False
    assert ExportValidator.validate_cyclonedx_export(missing_keys) is False

def test_validate_html_export():
    valid = "<html><body><h1>Report</h1></body></html>"
    invalid = "just some text"
    
    assert ExportValidator.validate_html_export(valid) is True
    assert ExportValidator.validate_html_export(invalid) is False

def test_validate_sarif_export():
    valid = json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Test Tool",
                    "rules": []
                }
            },
            "results": []
        }]
    })
    invalid_version = json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "1.0.0",
        "runs": []
    })
    missing_keys = json.dumps({
        "version": "2.1.0"
    })
    
    assert ExportValidator.validate_sarif_export(valid) is True
    assert ExportValidator.validate_sarif_export(invalid_version) is False
    assert ExportValidator.validate_sarif_export(missing_keys) is False

