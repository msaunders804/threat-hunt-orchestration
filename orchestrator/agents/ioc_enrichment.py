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


def enrich_iocs(state: dict) -> dict:
    entities = state.get("entities", {})
    ips = entities.get("ips") or []
    domains = entities.get("domains") or []
    hashes = entities.get("hashes") or []

    results: list[dict] = []
    for ip in ips:
        results.append(_lookup("ips", ip))
    for domain in domains:
        results.append(_lookup("domains", domain))
    for h in hashes:
        results.append(_lookup("hashes", h))

    by_rep = lambda r, rep: [x for x in r if x.get("reputation") == rep]

    agent_output = {
        "results": results,
        "total": len(results),
        "malicious_count": len(by_rep(results, "malicious")),
        "suspicious_count": len(by_rep(results, "suspicious")),
        "clean_count": len(by_rep(results, "clean")),
        "unknown_count": len(by_rep(results, "unknown")),
    }

    logger.info(
        "IOC enrichment: total=%d malicious=%d suspicious=%d clean=%d unknown=%d",
        agent_output["total"],
        agent_output["malicious_count"],
        agent_output["suspicious_count"],
        agent_output["clean_count"],
        agent_output["unknown_count"],
    )

    return {**state, "agent_output": agent_output}
