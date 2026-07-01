"""External threat-intel connectors, gated for air-gapped deployments.

Every function here is a no-op unless BOTH `EXTERNAL_TI_ENABLED=true` AND the
relevant API key is set. In the air-gapped/GovCloud deployment the flag stays
false, so no egress is ever attempted — the branch runs entirely on local ES +
the offline reputation feed.

Uses only the stdlib (`urllib`) so enabling external TI adds no dependency, and
wraps every call so a network failure degrades to "no external data" rather than
breaking the hunt.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request

from ...config import settings

logger = logging.getLogger(__name__)

_TIMEOUT = 8  # seconds; keep hunts responsive if a provider is slow


def enabled() -> bool:
    return settings.external_ti_enabled


def _get_json(url: str, headers: dict[str, str]) -> dict | None:
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        logger.warning("External TI request failed (%s): %s", url, exc)
        return None


def _virustotal(ioc: str, ioc_type: str) -> dict | None:
    if not settings.virustotal_api_key:
        return None
    path = {"ips": "ip_addresses", "domains": "domains", "hashes": "files"}.get(ioc_type)
    if not path:
        return None
    data = _get_json(
        f"https://www.virustotal.com/api/v3/{path}/{ioc}",
        {"x-apikey": settings.virustotal_api_key},
    )
    if not data:
        return None
    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    return {
        "source": "virustotal",
        "reputation": "malicious" if malicious else "clean",
        "category": f"{malicious} engines flagged" if malicious else "no detections",
    }


def enrich_external(ioc: str, ioc_type: str) -> dict | None:
    """Best-effort external enrichment for one indicator. None if disabled/unknown."""
    if not enabled():
        return None
    # Extend with Shodan / OTX connectors as needed; VirusTotal covers all types.
    return _virustotal(ioc, ioc_type)
