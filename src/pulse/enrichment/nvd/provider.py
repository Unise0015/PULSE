import httpx
import logging
import time
from typing import Optional, List, Dict, Any
from pulse.config import get_setting

logger = logging.getLogger(__name__)

_MAX_RETRIES = 2
_RETRY_DELAY = 2.0

# NVD API v2 CVEs endpoint
_NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NVDCPEProvider:
    """Retrieves CVE records from NVD by CPE name.
    
    This module is responsible ONLY for API communication.
    It does not perform version matching or correlation decisions.
    """

    def __init__(self):
        self.api_key = get_setting("NVD_API_KEY")

        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        self.client = httpx.Client(timeout=20.0, headers=headers)
        self.delay_between_reqs = 0.6 if self.api_key else 6.0
        self._warned_unavailable = False

    def fetch_cves_by_cpe(self, cpe_name: str) -> Optional[List[Dict[str, Any]]]:
        """Query NVD for all CVEs matching a CPE name.
        
        Args:
            cpe_name: A CPE 2.3 string, e.g. "cpe:2.3:a:vercel:next.js:*:*:*:*:*:*:*:*"
                      Wildcards are acceptable; NVD will return all matching CVEs.
        
        Returns:
            List of raw CVE dicts from NVD, or None on failure.
        """
        for attempt in range(_MAX_RETRIES + 1):
            try:
                resp = self.client.get(
                    _NVD_API_URL,
                    params={"cpeName": cpe_name}
                )
                resp.raise_for_status()

                data = resp.json()
                vulnerabilities = data.get("vulnerabilities", [])

                # Extract the 'cve' dict from each vulnerability wrapper
                cves = [
                    v.get("cve", {})
                    for v in vulnerabilities
                    if v.get("cve")
                ]

                time.sleep(self.delay_between_reqs)
                return cves

            except httpx.TimeoutException:
                if attempt < _MAX_RETRIES:
                    time.sleep(_RETRY_DELAY)
                else:
                    if not self._warned_unavailable:
                        logger.warning(
                            "NVD unavailable (timeout) for CPE query: %s", cpe_name
                        )
                        self._warned_unavailable = True
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 403:
                    logger.warning("NVD API key missing or invalid. CPE correlation limited.")
                elif e.response.status_code == 404:
                    logger.debug("No NVD results for CPE: %s", cpe_name)
                    return []
                else:
                    logger.warning("NVD HTTP %s for CPE %s.", e.response.status_code, cpe_name)
                break
            except Exception as e:
                if not self._warned_unavailable:
                    logger.warning("NVD unavailable (%s). CPE correlation limited.", e)
                    self._warned_unavailable = True
                break

        return None

    def close(self) -> None:
        """Close the HTTP client."""
        self.client.close()
