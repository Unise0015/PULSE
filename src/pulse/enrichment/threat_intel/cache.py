import hashlib
import json
import logging
import sqlite3
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

from pulse.history.db import get_db_path

logger = logging.getLogger(__name__)

_CACHE_TABLE_DDL = """
    CREATE TABLE IF NOT EXISTS threat_intel_cache (
        cache_key     TEXT PRIMARY KEY,
        cve_id        TEXT,
        intel_json    TEXT,
        timestamp     DATETIME DEFAULT CURRENT_TIMESTAMP
    )
"""


class ThreatIntelCache:
    """Unified cache for threat intelligence lookups by CVE ID.
    
    Keys are sha256(cve_id) to efficiently store/retrieve EPSS, KEV,
    and ATT&CK enrichment data.
    """

    CACHE_TTL_HOURS = 24

    def __init__(self, ttl_hours: int = CACHE_TTL_HOURS):
        self.db_path = get_db_path()
        self.ttl_hours = ttl_hours
        self._ensure_table()

    def _ensure_table(self) -> None:
        """Create the threat_intel_cache table if it doesn't exist."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(_CACHE_TABLE_DDL)
                conn.commit()
        except sqlite3.Error as e:
            logger.warning("Failed to create threat intel cache table: %s", e)

    @staticmethod
    def make_key(cve_id: str) -> str:
        """Generate a determinist cache key for a CVE."""
        return hashlib.sha256(cve_id.encode("utf-8")).hexdigest()

    def get(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve cached threat intelligence for a CVE, respecting TTL."""
        cache_key = self.make_key(cve_id)
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT intel_json, timestamp FROM threat_intel_cache WHERE cache_key = ?",
                    (cache_key,),
                )
                row = cursor.fetchone()
                if not row:
                    return None

                timestamp = datetime.strptime(row[1], "%Y-%m-%d %H:%M:%S")
                if datetime.now() - timestamp >= timedelta(hours=self.ttl_hours):
                    return None

                return json.loads(row[0])
        except (json.JSONDecodeError, ValueError, sqlite3.Error) as e:
            logger.warning("Corrupted threat intel cache entry for %s: %s", cve_id, e)
            self._purge(cve_id)
            return None

    def put(self, cve_id: str, intel_data: Dict[str, Any]) -> None:
        """Store threat intelligence data for a CVE."""
        cache_key = self.make_key(cve_id)
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """REPLACE INTO threat_intel_cache
                       (cache_key, cve_id, intel_json, timestamp)
                       VALUES (?, ?, ?, CURRENT_TIMESTAMP)""",
                    (cache_key, cve_id, json.dumps(intel_data)),
                )
                conn.commit()
        except sqlite3.Error as e:
            logger.warning("Threat intel cache write failed for %s: %s", cve_id, e)

    def _purge(self, cve_id: str) -> None:
        """Remove a corrupted cache entry."""
        cache_key = self.make_key(cve_id)
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "DELETE FROM threat_intel_cache WHERE cache_key = ?",
                    (cache_key,),
                )
                conn.commit()
        except sqlite3.Error:
            pass
