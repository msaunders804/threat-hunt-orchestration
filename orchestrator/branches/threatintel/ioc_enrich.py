import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

_DATA_PATH = Path(__file__).parent.parent.parent / "data" / "ioc_mock.json"
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
        return {"ioc": value, "ioc_type": ioc_type, "found": True, **entry}
    return {"ioc": value, "ioc_type": ioc_type, "found": False, "reputation": "unknown"}


def enrich_iocs(ips: list[str], domains: list[str], hashes: list[str]) -> str:
    """Look up IP addresses, domain names, and file hashes against the threat intelligence database.

    Use this tool when the user wants to check whether IPs, domains, or file hashes are
    malicious, suspicious, or known bad. Returns reputation and threat category for each indicator.

    Args:
        ips: List of IPv4 addresses to look up (e.g. ["1.2.3.4", "5.6.7.8"])
        domains: List of domain names to check (e.g. ["evil.com", "bad.net"])
        hashes: List of MD5/SHA1/SHA256 file hashes to check
    """
    results: list[dict] = []
    for ip in ips:
        results.append(_lookup("ips", ip))
    for domain in domains:
        results.append(_lookup("domains", domain))
    for h in hashes:
        results.append(_lookup("hashes", h))

    by_rep = lambda r, rep: [x for x in r if x.get("reputation") == rep]

    summary = {
        "results": results,
        "total": len(results),
        "malicious_count": len(by_rep(results, "malicious")),
        "suspicious_count": len(by_rep(results, "suspicious")),
        "clean_count": len(by_rep(results, "clean")),
        "unknown_count": len(by_rep(results, "unknown")),
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
