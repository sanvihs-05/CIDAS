"""OSV.dev vulnerability lookup client.

Queries the open-source vulnerability database (https://osv.dev) for known
npm security advisories.  The client is intentionally lenient: any network or
parse failure returns an empty result so callers can degrade gracefully.
"""
from __future__ import annotations

import httpx

from .logger import get_logger

log = get_logger(__name__)

_OSV_URL = "https://api.osv.dev/v1/query"
_TIMEOUT = httpx.Timeout(5.0)

# Keywords that unambiguously indicate intentional malware, not ordinary CVEs.
# Keep this list narrow — prototype-pollution/ReDoS advisories also use words
# like "credential" and "destructive" in context, so we only include phrases
# that are specific to supply-chain attacks.
_MALWARE_KEYWORDS = frozenset({
    "backdoor",
    "supply-chain compromise",
    "supply chain compromise",
    "cryptominer",
    "crypto miner",
    "trojan",
    "wiper",
    "intentionally malicious",
})


def _empty() -> dict:
    return {"vuln_count": 0, "has_malware": False, "vuln_ids": []}


def _classify_vulns(vulns: list[dict]) -> tuple[bool, list[str]]:
    """Return (has_malware, vuln_id_list) from a raw OSV vuln list."""
    has_malware = False
    ids: list[str] = []
    for v in vulns:
        vid = v.get("id") or ""
        if vid:
            ids.append(vid)
        # MAL- prefix is the OSV malicious-packages database — always malware.
        if not has_malware and vid.startswith("MAL-"):
            has_malware = True
            continue
        # Keyword fallback for entries not yet in the malicious-packages DB.
        if not has_malware:
            text = ((v.get("summary") or "") + " " + (v.get("details") or "")).lower()
            if any(kw in text for kw in _MALWARE_KEYWORDS):
                has_malware = True
    return has_malware, ids[:5]


async def check_osv(package_name: str) -> dict:
    """Return OSV findings for *package_name* on the npm ecosystem.

    Result keys:
      - ``vuln_count``  – total number of known advisories
      - ``has_malware`` – True when any advisory describes intentional malware
      - ``vuln_ids``    – list of up to 5 advisory IDs (e.g. GHSA-*, MAL-*)
    """
    payload = {"package": {"name": package_name, "ecosystem": "npm"}}
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(_OSV_URL, json=payload)
            if resp.status_code != 200:
                log.debug("OSV returned HTTP %s for %s", resp.status_code, package_name)
                return _empty()
            data = resp.json()
    except (httpx.TimeoutException, httpx.NetworkError, Exception) as exc:
        log.debug("OSV query failed for %s: %s", package_name, exc)
        return _empty()

    vulns = data.get("vulns") or []
    if not vulns:
        return _empty()

    has_malware, ids = _classify_vulns(vulns)
    return {"vuln_count": len(vulns), "has_malware": has_malware, "vuln_ids": ids}
