"""IOC reputation enrichment.

Local-first: every indicator is looked up against the offline reputation feed
(data/ioc_mock.json — swap for a real local feed in production). When external
TI is enabled (non-air-gapped), unknown indicators are augmented with
VirusTotal et al.

Two entry points:
  * `enrich_iocs(...)` — JSON-returning tool for the generalist agent.
  * `enrich(...)`      — typed `list[IOCResult]` for the threat-intel branch.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from ...services.threatintel.external import enrich_external
from ...state import IOCResult

logger = logging.getLogger(__name__)

_DATA_PATH = Path(__file__).parent.parent.parent.parent / "data" / "ioc_mock.json"
_ioc_db: dict | None = None


def _load_db() -> dict:
    global _ioc_db
    if _ioc_db is None:
        with open(_DATA_PATH, encoding="utf-8") as f:
            _ioc_db = json.load(f)
    return _ioc_db


def _lookup(ioc_type: str, value: str) -> dict:
    db = _load_db()
    entry = db.get(ioc_type, {}).get(value)
    if entry:
        return {"ioc": value, "ioc_type": ioc_type, "found": True, "source": "local", **entry}
    # Unknown locally — try external TI (no-op when disabled/air-gapped).
    ext = enrich_external(value, ioc_type)
    if ext:
        return {"ioc": value, "ioc_type": ioc_type, "found": True, **ext}
    return {
        "ioc": value,
        "ioc_type": ioc_type,
        "found": False,
        "reputation": "unknown",
        "source": "local",
    }


def enrich(ips: list[str], domains: list[str], hashes: list[str]) -> list[IOCResult]:
    """Typed enrichment for the branch pipeline."""
    rows: list[dict] = []
    for ip in ips:
        rows.append(_lookup("ips", ip))
    for domain in domains:
        rows.append(_lookup("domains", domain))
    for h in hashes:
        rows.append(_lookup("hashes", h))
    return [
        IOCResult(
            ioc=r["ioc"],
            ioc_type=r["ioc_type"],
            found=r.get("found", False),
            reputation=r.get("reputation", "unknown"),
            category=r.get("category", ""),
            source=r.get("source", "local"),
        )
        for r in rows
    ]


def enrich_iocs(ips: list[str], domains: list[str], hashes: list[str]) -> str:
    """Look up IP addresses, domain names, and file hashes against the threat intelligence database.

    Use this tool when the user wants to check whether IPs, domains, or file hashes are
    malicious, suspicious, or known bad. Returns reputation and threat category for each indicator.

    Args:
        ips: List of IPv4 addresses to look up (e.g. ["1.2.3.4", "5.6.7.8"])
        domains: List of domain names to check (e.g. ["evil.com", "bad.net"])
        hashes: List of MD5/SHA1/SHA256 file hashes to check
    """
    results = [r.model_dump() for r in enrich(ips, domains, hashes)]

    by_rep = lambda rep: [x for x in results if x.get("reputation") == rep]
    summary = {
        "results": results,
        "total": len(results),
        "malicious_count": len(by_rep("malicious")),
        "suspicious_count": len(by_rep("suspicious")),
        "clean_count": len(by_rep("clean")),
        "unknown_count": len(by_rep("unknown")),
    }
    logger.info(
        "IOC enrichment: total=%d malicious=%d suspicious=%d clean=%d unknown=%d",
        summary["total"],
        summary["malicious_count"],
        summary["suspicious_count"],
        summary["clean_count"],
        summary["unknown_count"],
    )
    return json.dumps(summary)
