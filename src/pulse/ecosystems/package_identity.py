from dataclasses import dataclass
from typing import Dict, Tuple, Optional, Any
import logging
import asyncio

logger = logging.getLogger(__name__)

@dataclass(frozen=True)
class PackageIdentity:
    """Canonical representation of a resolved software package identity."""
    name: str
    version: Optional[str]
    ecosystem: str
    registry: Optional[str] = None
    confidence: float = 0.0
    source: str = ""


# Mapping of popular, potentially ambiguous package names to their canonical ecosystems.
# Format: "package_name": ("ecosystem_name", "registry_name")
# Example: "bootstrap": ("npm", "npmjs.com")
#
# This serves as a high-confidence (+25 score) baseline for resolution.

KNOWN_PACKAGE_IDENTITIES: Dict[str, Tuple[str, str]] = {
    "php": ("Composer", "Packagist"),
    "python": ("Python", "PyPI"),
    "ruby": ("Ruby", "RubyGems"),
    "node": ("Node.js", "npm"),
    "nodejs": ("Node.js", "npm"),
    "rust": ("Rust", "crates.io"),
    "go": ("Go", "Go"),
    "golang": ("Go", "Go"),
    "nginx": ("Nginx", "Nginx"),
    "apache": ("Apache", "Apache"),
    "httpd": ("Apache", "Apache"),
    "bootstrap": ("Node.js", "npm"),
    "react": ("Node.js", "npm"),
    "jquery": ("Node.js", "npm"),
    "vue": ("Node.js", "npm"),
    "vue.js": ("Node.js", "npm"),
    "angular": ("Node.js", "npm"),
    "angular.js": ("Node.js", "npm"),
    "@angular/core": ("Node.js", "npm"),
    "lodash": ("Node.js", "npm"),
    "tailwind": ("Node.js", "npm"),
    "tailwindcss": ("Node.js", "npm"),
    "express": ("Node.js", "npm"),
    "next": ("Node.js", "npm"),
    "next.js": ("Node.js", "npm"),
    "nuxt": ("Node.js", "npm"),
    "nuxt.js": ("Node.js", "npm"),
    "svelte": ("Node.js", "npm"),
    "gatsby": ("Node.js", "npm"),
    "django": ("Python", "PyPI"),
    "flask": ("Python", "PyPI"),
    "fastapi": ("Python", "PyPI"),
    "requests": ("Python", "PyPI"),
    "numpy": ("Python", "PyPI"),
    "rails": ("Ruby", "RubyGems"),
    "rubyonrails": ("Ruby", "RubyGems"),
    "serde": ("Rust", "crates.io"),
    "tokio": ("Rust", "crates.io"),
    "laravel/framework": ("Composer", "Packagist"),
    "laravel": ("Composer", "Packagist"),
    "Newtonsoft.Json": ("NuGet", "NuGet"),
    "spring-core": ("Maven", "Maven Central"),
    "spring": ("Maven", "Maven Central"),
    "wordpress": ("WordPress", "WordPress"),
    "drupal": ("Drupal", "Drupal"),
    "phoenix": ("Hex", "Hex.pm"),
    "actions/checkout": ("GitHub Actions", "GitHub"),
    "hashicorp/aws": ("Terraform", "Terraform Registry"),
}

def get_known_identity(package_name: str) -> Tuple[Optional[str], Optional[str]]:
    """Return (ecosystem_name, registry_name) if known, else (None, None)."""
    return KNOWN_PACKAGE_IDENTITIES.get(package_name.lower(), (None, None))


def resolve_technology_package(
    name: str,
    version: Optional[str] = None,
    fingerprint: Optional[Any] = None,
) -> Optional[PackageIdentity]:
    """
    Canonical technology to package identity resolver.
    
    Resolution order:
    1. Explicit package identity on fingerprint if present.
    2. Local KNOWN_PACKAGE_IDENTITIES mapping.
    3. Technology catalog metadata (pulse.website.technology_catalog).
    4. Dynamic PackageResolutionService (querying registry plugins & ecosyste.ms with confidence >= 50).
    
    Returns:
        PackageIdentity or None if unresolved.
    """
    if not name or not name.strip():
        return None

    raw_name = name.strip()
    norm_name = raw_name.lower()
    clean_version = version.strip() if (version and isinstance(version, str) and version.strip()) else None

    # 1. Existing explicit package identity on fingerprint
    if fingerprint is not None:
        fp_eco = getattr(fingerprint, "ecosystem", None)
        fp_pkg = getattr(fingerprint, "package", None) or getattr(fingerprint, "package_name", None)
        if fp_eco and fp_pkg:
            return PackageIdentity(
                name=fp_pkg,
                version=clean_version,
                ecosystem=fp_eco,
                registry=getattr(fingerprint, "registry", None) or getattr(fingerprint, "registry_name", None),
                confidence=float(getattr(fingerprint, "confidence", 100.0) or 100.0),
                source="fingerprint"
            )

    # 2. Local KNOWN_PACKAGE_IDENTITIES
    known_eco, known_reg = get_known_identity(norm_name)
    if known_eco:
        canonical_name = norm_name
        if norm_name in ("angular", "angular.js"):
            canonical_name = "@angular/core"
        elif norm_name in ("tailwind",):
            canonical_name = "tailwindcss"
        elif norm_name in ("next.js",):
            canonical_name = "next"
        elif norm_name in ("nuxt.js",):
            canonical_name = "nuxt"
        elif norm_name in ("laravel",):
            canonical_name = "laravel/framework"
        elif norm_name in ("spring",):
            canonical_name = "spring-core"
        elif norm_name in ("rubyonrails",):
            canonical_name = "rails"

        return PackageIdentity(
            name=canonical_name,
            version=clean_version,
            ecosystem=known_eco,
            registry=known_reg,
            confidence=95.0,
            source="known_identities"
        )

    # 3. Technology catalog metadata
    try:
        from pulse.website.technology_catalog import TECHNOLOGY_CATALOG
        catalog_entry = None
        for k, entry in TECHNOLOGY_CATALOG.items():
            if norm_name == k.lower() or norm_name in [a.lower() for a in entry.get("aliases", [])]:
                catalog_entry = entry
                break

        if catalog_entry:
            cat_pkg = catalog_entry.get("package")
            cat_eco = catalog_entry.get("ecosystem")
            if cat_pkg and cat_eco:
                return PackageIdentity(
                    name=cat_pkg,
                    version=clean_version,
                    ecosystem=cat_eco,
                    registry=catalog_entry.get("registry"),
                    confidence=90.0,
                    source="catalog"
                )
    except Exception as e:
        logger.debug("Catalog lookup failed in resolve_technology_package: %s", e)

    # 4. Dynamic PackageResolutionService (confidence threshold >= 50)
    try:
        from pulse.ecosystems.package_resolution import PackageResolutionService
        resolver = PackageResolutionService()
        
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                result = pool.submit(asyncio.run, resolver.resolve(raw_name, clean_version)).result()
        else:
            result = asyncio.run(resolver.resolve(raw_name, clean_version))

        if result and result.package_exists and result.ecosystem and (result.confidence or 0) >= 50:
            return PackageIdentity(
                name=result.package_name,
                version=clean_version,
                ecosystem=result.ecosystem,
                registry=result.registry_name,
                confidence=float(result.confidence or 75.0),
                source="package_resolution_service"
            )
    except Exception as e:
        logger.debug("PackageResolutionService resolution failed for '%s': %s", raw_name, e)

    return None
