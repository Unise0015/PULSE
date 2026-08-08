import json
from pulse.reporting.models import ReportModel, Severity
from pulse.reporting.renderers.base import BaseRenderer
from pulse.reporting.renderers.json_renderer import ReportJSONEncoder

class SARIFRenderer(BaseRenderer):
    """SARIF 2.1.0 compliant JSON renderer for CI/CD integrations."""

    def render(self, report: ReportModel) -> str:
        rules = []
        results = []

        eco_file_map = {
            "python": "requirements.txt",
            "pypi": "requirements.txt",
            "npm": "package.json",
            "node": "package.json",
            "node.js": "package.json",
            "cargo": "Cargo.lock",
            "rust": "Cargo.lock",
            "go": "go.mod",
            "composer": "composer.json",
            "packagist": "composer.json",
            "rubygems": "Gemfile.lock",
            "ruby": "Gemfile.lock",
            "nuget": "packages.config",
            "maven": "pom.xml"
        }

        seen_rules = set()
        for f in report.findings:
            cve_id = f.cve_id or "UNKNOWN-CVE"
            if cve_id not in seen_rules:
                seen_rules.add(cve_id)
                level = "error" if f.severity in (Severity.CRITICAL, Severity.HIGH) else ("warning" if f.severity == Severity.MEDIUM else "note")
                rule = {
                    "id": cve_id,
                    "shortDescription": {
                        "text": f"Vulnerability in {f.package_name}: {cve_id}"
                    },
                    "fullDescription": {
                        "text": f.description or f"Vulnerability {cve_id}"
                    },
                    "properties": {
                        "cvssScore": f.cvss_score,
                        "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                        "epssScore": f.epss_percent,
                        "kevMatch": f.kev_match,
                        "riskHeatScore": f.risk_heat_score,
                        "attackTechniques": f.attack_techniques or []
                    }
                }
                if f.nvd_url:
                    rule["helpUri"] = f.nvd_url
                rules.append(rule)

            eco = (f.ecosystem or "").lower()
            file_name = eco_file_map.get(eco, "lockfile")
            level = "error" if f.severity in (Severity.CRITICAL, Severity.HIGH) else ("warning" if f.severity == Severity.MEDIUM else "note")

            msg_text = f"Package '{f.package_name}' version {f.package_version} has vulnerability {cve_id} (CVSS: {f.cvss_score}, EPSS: {f.epss_percent}, KEV: {'yes' if f.kev_match else 'no'}, Risk Score: {f.risk_heat_score})"
            if f.fix_version:
                msg_text += f". Recommended fix: Upgrade to version {f.fix_version}"
            if f.remediation_command:
                msg_text += f" ({f.remediation_command})"

            result = {
                "ruleId": cve_id,
                "level": level,
                "message": {
                    "text": msg_text
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": file_name
                            },
                            "region": {
                                "startLine": 1
                            }
                        }
                    }
                ]
            }
            results.append(result)

        sarif_data = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "PULSE CLI",
                            "version": report.metadata.pulse_version,
                            "rules": rules
                        }
                    },
                    "results": results
                }
            ]
        }

        return json.dumps(sarif_data, indent=2, ensure_ascii=False, cls=ReportJSONEncoder)
