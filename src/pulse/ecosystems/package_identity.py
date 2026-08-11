from typing import Dict, Tuple

# Mapping of popular, potentially ambiguous package names to their canonical ecosystems.
# Format: "package_name": ("ecosystem_name", "registry_name")
# Example: "bootstrap": ("npm", "npmjs.com")
# 
# This serves as a high-confidence (+25 score) baseline for resolution.

KNOWN_PACKAGE_IDENTITIES: Dict[str, Tuple[str, str]] = {
    "bootstrap": ("Node.js", "npm"),
    "react": ("Node.js", "npm"),
    "jquery": ("Node.js", "npm"),
    "django": ("Python", "PyPI"),
    "flask": ("Python", "PyPI"),
    "rails": ("Ruby", "RubyGems"),
    "serde": ("Rust", "crates.io"),
    "laravel/framework": ("Composer", "Packagist"),
    "Newtonsoft.Json": ("NuGet", "NuGet"),
    "spring-core": ("Maven", "Maven Central"),
    "lodash": ("Node.js", "npm"),
    "express": ("Node.js", "npm"),
    "requests": ("Python", "PyPI"),
    "numpy": ("Python", "PyPI"),
    "tokio": ("Rust", "crates.io"),
}

def get_known_identity(package_name: str) -> Tuple[str, str]:
    """Return (ecosystem_name, registry_name) if known, else (None, None)."""
    return KNOWN_PACKAGE_IDENTITIES.get(package_name.lower(), (None, None))
