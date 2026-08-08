from typing import Optional
from pulse.website.technology_catalog import TECHNOLOGY_CATALOG

def resolve_technology(tech_name: str) -> Optional[str]:
    """Resolve a raw technology name to its normalized catalog key.
    
    Args:
        tech_name: Raw technology name string (e.g. "wp", "Next.js", "nextjs")
        
    Returns:
        Normalized key from TECHNOLOGY_CATALOG (e.g. "wordpress", "next.js"),
        or None if the technology is not supported in the catalog.
    """
    if not tech_name:
        return None
        
    cleaned = tech_name.strip().lower()
    for key, info in TECHNOLOGY_CATALOG.items():
        if cleaned == key.lower():
            return key
        if cleaned in [a.lower() for a in info.get("aliases", [])]:
            return key
            
    return None
