"""IOC extraction + Elasticsearch hunt.

Pulls candidate indicators (IPv4, domains, file hashes) out of free-form analyst
text, then asks the ES seam where those indicators actually appear in the
environment (which internal hosts, how often, first/last seen). This turns a
reputation list into an environment-grounded hunt.
"""

from __future__ import annotations

import logging
import re

from ...services.elasticsearch import get_es_client

logger = logging.getLogger(__name__)

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HASH = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")
# Domain: at least one dot, a TLD of 2+ letters; excludes bare IPs (handled above).
_DOMAIN = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")


def extract_indicators(text: str) -> dict[str, list[str]]:
    text = text or ""
    ips = _dedupe(_IPV4.findall(text))
    hashes = _dedupe(_HASH.findall(text))
    # Remove anything that looks like an IP from the domain matches.
    domains = [d for d in _dedupe(_DOMAIN.findall(text)) if not _IPV4.fullmatch(d)]
    return {"ips": ips, "domains": domains, "hashes": hashes}


def _dedupe(items: list[str]) -> list[str]:
    seen: list[str] = []
    for i in items:
        if i not in seen:
            seen.append(i)
    return seen


def search_environment(ips: list[str], domains: list[str], hashes: list[str]) -> list[dict]:
    """Return ES hits for the given indicators (empty if none appear)."""
    if not (ips or domains or hashes):
        return []
    hits = get_es_client().search_iocs(ips, domains, hashes)
    logger.info("IOC ES search: %d hits", len(hits))
    return hits
