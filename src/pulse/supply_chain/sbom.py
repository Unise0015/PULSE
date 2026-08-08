import json
import uuid
from typing import Dict, Any, List
from datetime import datetime, timezone
from pulse.domain.models import ScanResult, VulnerabilityFinding
from pulse import __version__

def get_purl(ecosystem: str, name: str, version: str) -> str:
    """Generate a Package URL (purl)."""
    eco_map = {
        "python": "pypi",
        "pypi": "pypi",
        "npm": "npm",
        "node": "npm",
        "go": "golang",
        "golang": "golang",
        "java": "maven",
        "maven": "maven",
        "ruby": "gem",
        "gem": "gem",
        "rust": "cargo",
        "cargo": "cargo"
    }
    eco = eco_map.get(ecosystem.lower(), ecosystem.lower())
    # Note: real purls often need url encoding, but for basic use this is fine.
    return f"pkg:{eco}/{name}@{version}"

class CycloneDXExporter:
    """Generates CycloneDX v1.4 SBOM from a ScanResult."""
    
    def __init__(self, scan: ScanResult):
        self.scan = scan

    def generate(self) -> Dict[str, Any]:
        """Generate the SBOM JSON structure."""
        
        # We need unique components from findings.
        # But wait, what if packages are clean? 
        # The ScanResult findings only contain vulnerable packages.
        # Since we only track packages with CVEs in findings currently, 
        # the SBOM will be a "Vulnerable Component Inventory".
        # If we had access to `scan.all_packages`, we could include them all.
        
        components = {}
        vuln_map = {}
        
        for f in self.scan.findings:
            purl = get_purl(f.package.ecosystem, f.package.name, f.package.version)
            bom_ref = f"pkg:{f.package.name}@{f.package.version}"
            
            # Create or update component
            if bom_ref not in components:
                components[bom_ref] = {
                    "type": "library",
                    "bom-ref": bom_ref,
                    "name": f.package.name,
                    "version": f.package.version,
                    "purl": purl,
                    "properties": []
                }
                
            # Aggregate security enrichments on component properties
            c_props = components[bom_ref]["properties"]
            
            # Helper to append/merge properties
            def merge_prop(name, new_val):
                for p in c_props:
                    if p["name"] == name:
                        existing = set(p["value"].split(","))
                        existing.update(new_val.split(","))
                        p["value"] = ",".join(sorted(existing))
                        return
                c_props.append({"name": name, "value": new_val})

            t_ids = [t.technique_id for t in getattr(f, "attack_techniques", [])]
            t_names = [t.tactic for t in getattr(f, "attack_techniques", [])]
            
            if t_ids:
                merge_prop("pulse.attack_techniques", ",".join(t_ids))
            if t_names:
                merge_prop("pulse.attack_tactics", ",".join(t_names))
            if f.kev_match:
                merge_prop("pulse.kev_match", "true")
            if getattr(f, "exploit_intelligence", None):
                merge_prop("pulse.exploit_maturity", f.exploit_intelligence.exploit_maturity)
                
            # Create or update Vulnerability
            vuln_id = f.cve_id
            if vuln_id not in vuln_map:
                vuln_obj = {
                    "id": vuln_id,
                    "source": { "name": f.source },
                    "ratings": [
                        {
                            "source": { "name": "NVD" },
                            "score": f.cvss_score,
                            "severity": f.cvss_severity.lower(),
                            "method": "CVSSv31" if f.cvss_score > 0 else "other"
                        }
                    ],
                    "description": f.description,
                    "affects": []
                }
                if f.cwe:
                    try:
                        cwe_int = int(f.cwe.replace("CWE-", ""))
                        vuln_obj["cwes"] = [cwe_int]
                    except ValueError:
                        pass
                        
                vuln_obj["properties"] = [
                    { "name": "pulse.epss_score", "value": str(f.epss_score) },
                    { "name": "pulse.risk_heat_score", "value": str(f.risk_heat_score) }
                ]
                vuln_map[vuln_id] = vuln_obj
                
            # Add to affects
            affects_list = vuln_map[vuln_id]["affects"]
            if not any(a["ref"] == bom_ref for a in affects_list):
                affects_list.append({"ref": bom_ref})

        vulnerabilities = list(vuln_map.values())

        bom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "tools": [
                    {
                        "vendor": "PULSE",
                        "name": "PULSE CLI",
                        "version": __version__
                    }
                ]
            },
            "components": list(components.values()),
            "vulnerabilities": vulnerabilities
        }
        
        # Add dependency relationships if available
        if getattr(self.scan, "dependency_trees", None):
            dependencies_map = {}
            
            def add_dep(node):
                bom_ref = f"pkg:{node.package_name}@{node.version}"
                if bom_ref not in dependencies_map:
                    dependencies_map[bom_ref] = []
                
                for child in node.children:
                    child_ref = f"pkg:{child.package_name}@{child.version}"
                    if child_ref not in dependencies_map[bom_ref]:
                        dependencies_map[bom_ref].append(child_ref)
                    add_dep(child)
                    
            for root_node in self.scan.dependency_trees:
                add_dep(root_node)
                
            dependencies = [
                {"ref": ref, "dependsOn": depends_on} 
                for ref, depends_on in dependencies_map.items() 
                if depends_on or any(ref in d for d in dependencies_map.values())
            ]
            
            if dependencies:
                bom["dependencies"] = dependencies
        
        
        return bom

def export_cyclonedx(scan: ScanResult, output_path: str) -> None:
    """Export the ScanResult as a CycloneDX JSON file."""
    exporter = CycloneDXExporter(scan)
    bom = exporter.generate()
    
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(bom, f, indent=2)
