from typing import Optional, Tuple
from pulse.website.technology_catalog import TECHNOLOGY_CATALOG

def get_cpe_candidate(tech_key: str, version: Optional[str]) -> Optional[str]:
    """Build a CPE 2.3 string for a given technology and resolved version.
    
    Args:
        tech_key: Normalized catalog key
        version: Mapped version string
        
    Returns:
        Full CPE 2.3 criteria string or None
    """
    tech = TECHNOLOGY_CATALOG.get(tech_key.lower())
    if not tech:
        return None
        
    cpe_base = tech.get("cpe")
    if not cpe_base:
        return None
        
    ver = version if version else "*"
    parts = cpe_base.split(":")
    if len(parts) >= 5:
        cpe_vendor = parts[3]
        cpe_product = parts[4]
        return f"cpe:2.3:a:{cpe_vendor}:{cpe_product}:{ver}:*:*:*:*:*:*:*"
        
    return cpe_base

def get_osv_package_for_tech(tech_key: str) -> Optional[Tuple[str, str]]:
    """Get the OSV package name and ecosystem for a technology.
    
    Args:
        tech_key: Normalized catalog key
        
    Returns:
        Tuple[package_name, ecosystem] or None
    """
    tech = TECHNOLOGY_CATALOG.get(tech_key.lower())
    if not tech:
        return None
        
    package = tech.get("package")
    ecosystem = tech.get("ecosystem")
    if package and ecosystem:
        return package, ecosystem
        
    return None
