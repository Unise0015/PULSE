import logging
import json
import sqlite3
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime, timedelta
import httpx
import asyncio

from pulse.history.db import get_db_path
from pulse.config import get_setting

logger = logging.getLogger(__name__)

class EcosystemsClient:
    """Client for ecosyste.ms API, handling retries, timeouts, and caching."""
    
    BASE_URL = "https://packages.ecosyste.ms/api/v1"
    
    def __init__(self):
        self.db_path = get_db_path()
        self._ensure_cache_tables()
        self.timeout = int(get_setting("ECOSYSTEMS_MS_TIMEOUT", "5"))
        self.max_retries = int(get_setting("ECOSYSTEMS_MS_MAX_RETRIES", "2"))
        self.contact_email = get_setting("ECOSYSTEMS_MS_CONTACT_EMAIL", "")
        self.enabled = get_setting("ECOSYSTEMS_MS_ENABLED", "true").lower() in ("true", "1", "yes")

    def _ensure_cache_tables(self):
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS ecosystems_ms_cache (
                        cache_key TEXT PRIMARY KEY,
                        response_data TEXT,
                        status_code INTEGER,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                conn.commit()
        except sqlite3.Error as e:
            logger.warning(f"Failed to initialize ecosyste.ms cache table: {e}")

    def _get_cache(self, key: str) -> Optional[Dict[str, Any]]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT response_data, status_code, updated_at FROM ecosystems_ms_cache WHERE cache_key = ?",
                    (key,)
                )
                row = cursor.fetchone()
                if row:
                    ts = datetime.strptime(row[2], "%Y-%m-%d %H:%M:%S")
                    if datetime.now() - ts < timedelta(hours=24):
                        return {
                            "data": json.loads(row[0]) if row[0] else None,
                            "status": row[1]
                        }
                    else:
                        cursor.execute("DELETE FROM ecosystems_ms_cache WHERE cache_key = ?", (key,))
                        conn.commit()
        except (sqlite3.Error, json.JSONDecodeError):
            pass
        return None

    def _set_cache(self, key: str, data: Optional[Any], status: int):
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "REPLACE INTO ecosystems_ms_cache (cache_key, response_data, status_code, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)",
                    (key, json.dumps(data) if data else None, status)
                )
                conn.commit()
        except sqlite3.Error:
            pass

    async def _request(self, endpoint: str, cache_key: str) -> tuple[Optional[Any], int]:
        """Perform HTTP GET request with retries and backoff."""
        if not self.enabled:
            return None, 0
            
        cached = self._get_cache(cache_key)
        if cached:
            return cached["data"], cached["status"]

        headers = {"User-Agent": "PULSE-Scanner/1.0"}
        if self.contact_email:
            headers["User-Agent"] += f" (mailto:{self.contact_email})"

        url = f"{self.BASE_URL}{endpoint}"
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for attempt in range(self.max_retries + 1):
                try:
                    resp = await client.get(url, headers=headers)
                    
                    if resp.status_code == 429:
                        if attempt < self.max_retries:
                            await asyncio.sleep(2 ** attempt)
                            continue
                        return None, 429
                        
                    if resp.status_code >= 500:
                        if attempt < self.max_retries:
                            await asyncio.sleep(2 ** attempt)
                            continue
                        return None, resp.status_code
                        
                    data = resp.json() if resp.status_code == 200 else None
                    self._set_cache(cache_key, data, resp.status_code)
                    return data, resp.status_code
                    
                except httpx.RequestError as e:
                    logger.debug(f"HTTP request failed: {e}")
                    if attempt < self.max_retries:
                        await asyncio.sleep(2 ** attempt)
                        continue
                    return None, 0
        return None, 0

    async def search_packages(self, name: str) -> List[Dict[str, Any]]:
        cache_key = f"package-search:{name.lower()}"
        endpoint = f"/packages/lookup?name={name}"
        data, status = await self._request(endpoint, cache_key)
        if status == 200 and isinstance(data, list):
            return data
        return []

    async def get_package(self, registry_name: str, package_name: str) -> Optional[Dict[str, Any]]:
        cache_key = f"package:{registry_name}:{package_name.lower()}"
        endpoint = f"/registries/{registry_name}/packages/{package_name}"
        data, status = await self._request(endpoint, cache_key)
        if status == 200 and isinstance(data, dict):
            return data
        return None

    async def get_package_version(self, registry_name: str, package_name: str, version: str) -> Optional[Dict[str, Any]]:
        cache_key = f"package-version:{registry_name}:{package_name.lower()}:{version}"
        endpoint = f"/registries/{registry_name}/packages/{package_name}/versions/{version}"
        data, status = await self._request(endpoint, cache_key)
        if status == 200 and isinstance(data, dict):
            return data
        return None
