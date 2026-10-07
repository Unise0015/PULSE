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


# Standalone software that is NOT in any package registry but IS tracked via NVD CPE.
# Format: "name": ("cpe_vendor", "cpe_product", "display_ecosystem_category")
STANDALONE_SOFTWARE_IDENTITIES: Dict[str, Tuple[str, str, str]] = {
    # Web Servers
    "nginx": ("nginx", "nginx", "Server"),
    "apache": ("apache", "http_server", "Server"),
    "httpd": ("apache", "http_server", "Server"),
    "apache http server": ("apache", "http_server", "Server"),
    "apache httpd": ("apache", "http_server", "Server"),
    "lighttpd": ("lighttpd", "lighttpd", "Server"),
    "caddy": ("caddyserver", "caddy", "Server"),
    "tomcat": ("apache", "tomcat", "Server"),
    "apache tomcat": ("apache", "tomcat", "Server"),
    "iis": ("microsoft", "internet_information_services", "Server"),
    # Cryptography / TLS
    "openssl": ("openssl", "openssl", "Cryptography"),
    "libssl": ("openssl", "openssl", "Cryptography"),
    "gnutls": ("gnu", "gnutls", "Cryptography"),
    # Databases
    "mysql": ("oracle", "mysql", "Database"),
    "mariadb": ("mariadb", "mariadb", "Database"),
    "postgresql": ("postgresql", "postgresql", "Database"),
    "postgres": ("postgresql", "postgresql", "Database"),
    "redis": ("redis", "redis", "Database"),
    "mongodb": ("mongodb", "mongodb", "Database"),
    "sqlite": ("sqlite", "sqlite", "Database"),
    "elasticsearch": ("elastic", "elasticsearch", "Database"),
    # SSH / Remote Access
    "openssh": ("openbsd", "openssh", "Server"),
    "openssh-server": ("openbsd", "openssh", "Server"),
    # DNS
    "bind": ("isc", "bind", "DNS"),
    "named": ("isc", "bind", "DNS"),
    "bind9": ("isc", "bind", "DNS"),
    # Utilities / Libraries
    "curl": ("haxx", "curl", "Utility"),
    "libcurl": ("haxx", "libcurl", "Utility"),
    "wget": ("gnu", "wget", "Utility"),
    "git": ("git-scm", "git", "Utility"),
    "sudo": ("sudo_project", "sudo", "Utility"),
    "bash": ("gnu", "bash", "Utility"),
    "zlib": ("zlib", "zlib", "Library"),
    "libxml2": ("xmlsoft", "libxml2", "Library"),
    "libpng": ("libpng", "libpng", "Library"),
    # Container / Orchestration
    "docker": ("docker", "docker", "Container"),
    "containerd": ("linuxfoundation", "containerd", "Container"),
    "kubernetes": ("kubernetes", "kubernetes", "Orchestration"),
    "k8s": ("kubernetes", "kubernetes", "Orchestration"),
    # Mail
    "postfix": ("postfix", "postfix", "Mail"),
    "exim": ("exim", "exim", "Mail"),
    "dovecot": ("dovecot", "dovecot", "Mail"),
    # Proxy / Load Balancer
    "haproxy": ("haproxy", "haproxy", "Proxy"),
    "squid": ("squid-cache", "squid", "Proxy"),
    "varnish": ("varnish-software", "varnish_cache", "Proxy"),
    "envoy": ("envoyproxy", "envoy", "Proxy"),
    # CMS (standalone installs, not package registry)
    "wordpress": ("wordpress", "wordpress", "CMS"),
    "joomla": ("joomla", "joomla", "CMS"),
    # Runtime / Interpreter
    "php": ("php", "php", "Runtime"),
    "perl": ("perl", "perl", "Runtime"),
    "python": ("python", "python", "Runtime"),
    "ruby": ("ruby-lang", "ruby", "Runtime"),
    "node.js": ("nodejs", "node.js", "Runtime"),
    "nodejs": ("nodejs", "node.js", "Runtime"),
}


def get_standalone_identity(name: str) -> Optional[Tuple[str, str, str]]:
    """Return (cpe_vendor, cpe_product, display_category) if standalone software, else None."""
    return STANDALONE_SOFTWARE_IDENTITIES.get(name.lower().strip())



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

    # Aliases have one owner. A technology named Angular denotes modern Angular;
    # the literal npm package "angular" remains AngularJS in package lookups.
    canonical_name, alias_eco, alias_reg = get_canonical_package_info(norm_name)
    known_eco, known_reg = get_known_identity(norm_name)
    known_eco, known_reg = alias_eco or known_eco, alias_reg or known_reg
    if norm_name == "angular":
        canonical_name = "@angular/core"
    if known_eco:
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


# Comprehensive canonical alias mappings for package managers
# Format: "alias_name": ("canonical_package_name", "ecosystem_name", "registry_name")
CANONICAL_PACKAGE_ALIASES: Dict[str, Tuple[str, str, str]] = {
    # Node.js / npm aliases
    "next.js": ("next", "Node.js", "npm"),
    "nextjs": ("next", "Node.js", "npm"),
    "nuxt.js": ("nuxt", "Node.js", "npm"),
    "nuxtjs": ("nuxt", "Node.js", "npm"),
    "vue.js": ("vue", "Node.js", "npm"),
    "vuejs": ("vue", "Node.js", "npm"),
    "react.js": ("react", "Node.js", "npm"),
    "reactjs": ("react", "Node.js", "npm"),
    "express.js": ("express", "Node.js", "npm"),
    "expressjs": ("express", "Node.js", "npm"),
    "moment.js": ("moment", "Node.js", "npm"),
    "momentjs": ("moment", "Node.js", "npm"),
    "three.js": ("three", "Node.js", "npm"),
    "threejs": ("three", "Node.js", "npm"),
    "d3.js": ("d3", "Node.js", "npm"),
    "d3js": ("d3", "Node.js", "npm"),
    "chart.js": ("chart.js", "Node.js", "npm"),
    "chartjs": ("chart.js", "Node.js", "npm"),
    "tailwind": ("tailwindcss", "Node.js", "npm"),
    "angular.js": ("angular", "Node.js", "npm"),
    "angularjs": ("angular", "Node.js", "npm"),
    # Composer / PHP aliases
    "laravel": ("laravel/framework", "Composer", "Packagist"),
    "symfony": ("symfony/symfony", "Composer", "Packagist"),
    # Maven / Java aliases
    "spring": ("org.springframework:spring-core", "Maven", "Maven Central"),
    "spring-core": ("org.springframework:spring-core", "Maven", "Maven Central"),
    # Ruby aliases
    "rubyonrails": ("rails", "Ruby", "RubyGems"),
    # Go aliases
    "golang": ("go", "Go", "Go"),
}

def get_canonical_package_info(package_name: str) -> Tuple[str, Optional[str], Optional[str]]:
    """Return (canonical_name, ecosystem, registry) for a given alias or raw package name."""
    norm = (package_name or "").strip().lower()
    if norm in CANONICAL_PACKAGE_ALIASES:
        return CANONICAL_PACKAGE_ALIASES[norm]
    return (package_name, None, None)
