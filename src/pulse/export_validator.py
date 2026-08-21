import json
from typing import Dict, Any, Optional

class ExportValidator:
    """Validates the structure and content of generated exports."""
    
    @classmethod
    def validate_json_export(cls, export_data: str) -> bool:
        """Validates that a JSON export contains the required structural keys."""
        try:
            data = json.loads(export_data)
        except json.JSONDecodeError:
            return False
            
        if not isinstance(data, dict):
            return False
            
        required_keys = {"findings", "summary"}
        if not required_keys.issubset(data.keys()):
            return False
            
        if not isinstance(data.get("findings"), list):
            return False
            
        if not isinstance(data.get("summary"), dict):
            return False
            
        return True

    @classmethod
    def validate_cyclonedx_export(cls, export_data: str) -> bool:
        """Validates CycloneDX SBOM schema compliance."""
        try:
            data = json.loads(export_data)
        except json.JSONDecodeError:
            return False
            
        if not isinstance(data, dict):
            return False
            
        # Check base required fields for our CycloneDX generator
        required_keys = {"bomFormat", "specVersion", "components", "vulnerabilities", "dependencies"}
        if not required_keys.issubset(data.keys()):
            return False
            
        if data.get("bomFormat") != "CycloneDX":
            return False
            
        return True

    @classmethod
    def validate_html_export(cls, export_data: str) -> bool:
        """Validates HTML exports contain required structural sections."""
        # Simple heuristic check for key sections
        lower_html = export_data.lower()
        
        # Depending on what we export, check if critical tags exist
        if "<html" not in lower_html or "</html>" not in lower_html:
            return False
            
        # We might have technology inventory, dependency tree, attack paths in HTML
        # Ensure we have a body at least
        if "<body" not in lower_html:
            return False
            
        return True
