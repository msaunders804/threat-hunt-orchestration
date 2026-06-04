import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

_DATA_PATH = Path(__file__).parent.parent.parent.parent / "data" / "ioc_mock.json"
_ioc_db: dict | None = None


def _load_db() -> dict:
    global _ioc_db
    if _ioc_db is None:
        with open(_DATA_PATH, encoding="utf-8") as f:
            _ioc_db = json.load(f)
    return _ioc_db


def lookup_ip(ip: str) -> str:
    """Look up threat intelligence and reputation for an IPv4 address.

    Returns reputation (malicious/suspicious/clean/unknown), threat category,
    associated campaigns, and a description of observed activity.

    Args:
        ip: IPv4 address to look up (e.g. "198.51.100.10")
    """
    entry = _load_db().get("ips", {}).get(ip)
    if entry:
        result = {"ioc": ip, "ioc_type": "ip", "found": True, **entry}
    else:
        result = {"ioc": ip, "ioc_type": "ip", "found": False, "reputation": "unknown"}
    logger.debug("lookup_ip(%s) -> %s", ip, result.get("reputation"))
    return json.dumps(result)


def lookup_domain(domain: str) -> str:
    """Look up threat intelligence and reputation for a domain name.

    Returns reputation (malicious/suspicious/clean/unknown), threat category,
    associated campaigns, and a description of observed activity.

    Args:
        domain: Domain name to look up (e.g. "evildomain.xyz")
    """
    entry = _load_db().get("domains", {}).get(domain)
    if entry:
        result = {"ioc": domain, "ioc_type": "domain", "found": True, **entry}
    else:
        result = {"ioc": domain, "ioc_type": "domain", "found": False, "reputation": "unknown"}
    logger.debug("lookup_domain(%s) -> %s", domain, result.get("reputation"))
    return json.dumps(result)


def lookup_hash(hash_value: str) -> str:
    """Look up threat intelligence for a file hash (MD5, SHA1, or SHA256).

    Returns reputation, malware family, and a description of observed usage.

    Args:
        hash_value: MD5, SHA1, or SHA256 hash to look up
    """
    entry = _load_db().get("hashes", {}).get(hash_value)
    if entry:
        result = {"ioc": hash_value, "ioc_type": "hash", "found": True, **entry}
    else:
        result = {"ioc": hash_value, "ioc_type": "hash", "found": False, "reputation": "unknown"}
    logger.debug("lookup_hash(%s) -> %s", hash_value[:16], result.get("reputation"))
    return json.dumps(result)
