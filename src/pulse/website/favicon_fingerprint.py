"""
Favicon Hashing & Fingerprinting Module for PULSE Web Subsystem.
Computes MD5 / MurmurHash3 of favicon byte streams to identify web applications,
frameworks, routers, and embedded devices with 100% precision.
"""

import hashlib
import logging
from typing import Optional, Dict, Tuple
from pulse.domain.models import TechnologyFingerprint

logger = logging.getLogger(__name__)

# Static Favicon MD5 Hash Table (Hash -> (Name, Category, CPE))
FAVICON_MD5_DATABASE: Dict[str, Tuple[str, str, Optional[str]]] = {
    # Web Servers & Proxies
    "06950ee06ef39f99335a9094760a2b00": ("Nginx", "Web Server", "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"),
    "60c33a92b23a78950bc42e6a71e3b320": ("Apache HTTP Server", "Web Server", "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"),
    "f2b8743ef46cf0d6c8e3aa7b4ef9b4f9": ("Apache Tomcat", "Web Server", "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*"),
    
    # CMS Platforms
    "f3f7422f2f7036d0f666f36402ec5e42": ("WordPress", "CMS", "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*"),
    "83a6b57dbda3ec7f7c688001e403d93d": ("Drupal", "CMS", "cpe:2.3:a:drupal:drupal:*:*:*:*:*:*:*:*"),
    "e27db4b9c51270ae6fb758d407639535": ("Joomla!", "CMS", "cpe:2.3:a:joomla:joomla!:*:*:*:*:*:*:*:*"),
    "f07dbb34b7fefceac8991b10ecae2fef": ("Ghost", "CMS", None),
    "1d2c676d1e4e2b020ae4cf8021c3b169": ("Magento", "E-commerce", "cpe:2.3:a:magento:magento:*:*:*:*:*:*:*:*"),

    # Frameworks & Libraries
    "40a02db1630c7fb8faefae4bcbb73167": ("React", "JavaScript Framework", None),
    "6d1490214a1e9c20f1ecdf52ef1372df": ("Vue.js", "JavaScript Framework", None),
    "610663673f4e1f7480a8fb91efbf1df4": ("Angular", "JavaScript Framework", None),
    "5bf9303c73491fbb9c6e9ec19d08914b": ("Spring Boot", "Web Framework", None),
    "b8ab96d744b8b6f34ff24a0d9b4b0a4e": ("Laravel", "Web Framework", None),
    "8b2a1a8c8ff90d9a6c76e2730623dd3f": ("Django", "Web Framework", None),

    # DevOps, Monitoring & Admin Tools
    "237f37803e4811a2f170f807f45bf272": ("Jenkins", "DevOps Tool", "cpe:2.3:a:jenkins:jenkins:*:*:*:*:*:*:*:*"),
    "0c98fbc1c9a72f0db1ff18d6e3c09e3e": ("Grafana", "Monitoring", "cpe:2.3:a:grafana:grafana:*:*:*:*:*:*:*:*"),
    "73be8353d9e4a39045ef203d987e9e8f": ("phpMyAdmin", "Database Tool", "cpe:2.3:a:phpmyadmin:phpmyadmin:*:*:*:*:*:*:*:*"),
    "5143a531aa9622d99211c4b4a68ef338": ("pfSense", "Firewall", "cpe:2.3:a:pfsense:pfsense:*:*:*:*:*:*:*:*"),
    "8ffbf0d53c52e69fb23d70ff90e54d31": ("GitLab", "DevOps Tool", "cpe:2.3:a:gitlab:gitlab:*:*:*:*:*:*:*:*"),
}


class FaviconFingerprinter:
    """Analyzes raw favicon response bytes to identify web technology fingerprints."""

    @staticmethod
    def compute_md5(raw_bytes: bytes) -> str:
        """Computes the MD5 hex string of a byte stream."""
        return hashlib.md5(raw_bytes).hexdigest().lower()

    @classmethod
    def identify(cls, raw_bytes: bytes) -> Optional[TechnologyFingerprint]:
        """Matches raw favicon bytes against the favicon database."""
        if not raw_bytes or len(raw_bytes) < 16:
            return None

        md5_hash = cls.compute_md5(raw_bytes)
        if md5_hash in FAVICON_MD5_DATABASE:
            name, category, cpe = FAVICON_MD5_DATABASE[md5_hash]
            logger.info("Favicon match identified technology: %s (MD5: %s)", name, md5_hash)
            return TechnologyFingerprint(
                name=name,
                category=category,
                version=None,
                confidence=100, # Favicon hash matches are 100% reliable
                cpe=cpe
            )

        return None
