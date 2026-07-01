"""Top-talker analysis via the Elasticsearch seam.

Deterministic: asks the ES client (mock or live) for the busiest hosts and
normalizes them into `TrafficStat`. These stats also supply the edges for the
Obsidian network map.
"""

from __future__ import annotations

import logging

from ...services.elasticsearch import get_es_client
from ...state import TrafficStat

logger = logging.getLogger(__name__)


def top_talkers(limit: int = 10) -> list[TrafficStat]:
    rows = get_es_client().top_talkers(limit=limit)
    stats = [
        TrafficStat(
            ip=r.get("ip", ""),
            bytes_total=int(r.get("bytes_total", 0)),
            flows=int(r.get("flows", 0)),
            peers=list(r.get("peers", [])),
        )
        for r in rows
        if r.get("ip")
    ]
    logger.info("Top talkers: %d hosts", len(stats))
    return stats
