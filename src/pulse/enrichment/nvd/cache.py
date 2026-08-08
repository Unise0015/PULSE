import hashlib
import json
import logging
import sqlite3
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from pulse.history.db import get_db_path

logger = logging.getLogger(__name__)

_CACHE_TABLE_DDL = """
    CREATE TABLE IF NOT EXISTS nvd_cpe_correlation_cache (
        cache_key     TEXT PRIMARY KEY,
        cpe_string    TEXT,
        detected_version TEXT,
        cves_json     TEXT,
        cve_count     INTEGER,
        timestamp     DATETIME DEFAULT CURRENT_TIMESTAMP
    )
"""

# Default TTL.  Future --refresh-intel flag can override via constructor.
_DEFAULT_TTL_HOURS = 24


class NVDCorrelationCache:
    """Cache for NVD CPE-based CVE lookups.
    
    Keys are sha256(cpe_template:detected_version) so that
    "Next.js 14" and "Next.js 15" are cached independently.
    """

    def __init__(self, ttl_hours: int = _DEFAULT_TTL_HOURS):
        self.db_path = get_db_path()
        self.ttl_hours = ttl_hours
        self._ensure_table()

    def _ensure_table(self) -> None:
        """Create cache table if it does not exist."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(_CACHE_TABLE_DDL)
                conn.commit()
        except sqlite3.Error as e:
            logger.warning("Failed to create NVD correlation cache table: %s", e)

    @staticmethod
    def make_key(cpe_string: str, detected_version: Optional[str] = None) -> str:
        """Generate a version-aware cache key.
        
        Ensures that different detected versions of the same technology
        produce distinct cache entries.
        """
        raw = f"{cpe_string}:{detected_version or ''}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def get(self, cpe_string: str, detected_version: Optional[str] = None) -> Optional[List[Dict[str, Any]]]:
        """Retrieve cached CVE data, respecting TTL.
        
        Returns list of CVE dicts if cached and valid, None otherwise.
        """
        cache_key = self.make_key(cpe_string, detected_version)
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT cves_json, timestamp FROM nvd_cpe_correlation_cache WHERE cache_key = ?",
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
            logger.warning("Corrupted NVD correlation cache entry for %s: %s", cpe_string, e)
            self._purge(cpe_string, detected_version)
            return None

    def put(
        self,
        cpe_string: str,
        cves: List[Dict[str, Any]],
        detected_version: Optional[str] = None
    ) -> None:
        """Store CVE data for a CPE + version combination."""
        cache_key = self.make_key(cpe_string, detected_version)
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """REPLACE INTO nvd_cpe_correlation_cache
                       (cache_key, cpe_string, detected_version, cves_json, cve_count, timestamp)
                       VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)""",
                    (cache_key, cpe_string, detected_version or "", json.dumps(cves), len(cves)),
                )
                conn.commit()
        except sqlite3.Error as e:
            logger.warning("NVD correlation cache write failed for %s: %s", cpe_string, e)

    def _purge(self, cpe_string: str, detected_version: Optional[str] = None) -> None:
        """Remove a corrupted cache entry."""
        cache_key = self.make_key(cpe_string, detected_version)
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "DELETE FROM nvd_cpe_correlation_cache WHERE cache_key = ?",
                    (cache_key,),
                )
                conn.commit()
        except sqlite3.Error:
            pass
