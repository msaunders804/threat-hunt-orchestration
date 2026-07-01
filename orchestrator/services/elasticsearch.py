"""Elasticsearch access seam.

Both the network branch (top-talkers) and the threat-intel branch (IOC search)
depend on Elasticsearch. This module hides the difference between a live cluster
and local mock fixtures behind one `ESClient` protocol, selected by `ES_MODE`.

Building against `MockESClient` now means the branches are testable offline; the
swap to `LiveESClient` is env-only (`ES_MODE=live`, `ES_URL`, `ES_API_KEY`).

Field/index assumptions follow ECS + Beats/Zeek conventions and are configurable
via settings (`es_flow_index`, `es_event_index`).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Protocol, runtime_checkable

from ..config import settings

logger = logging.getLogger(__name__)

_MOCK_DIR = Path(__file__).parent.parent.parent / "data" / "es_mock"


@runtime_checkable
class ESClient(Protocol):
    """Minimal surface the agents need. Extend as new queries are added."""

    def top_talkers(self, limit: int = 10) -> list[dict]:
        """Return hosts ranked by traffic volume.

        Each item: {"ip", "bytes_total", "flows", "peers": [...]}.
        """
        ...

    def search_iocs(
        self, ips: list[str], domains: list[str], hashes: list[str]
    ) -> list[dict]:
        """Return event hits where any indicator appears.

        Each item: {"ioc", "ioc_type", "index", "count", "first_seen", "last_seen"}.
        """
        ...


# ── Mock implementation ──────────────────────────────────────────────────


class MockESClient:
    """Serves canned responses from data/es_mock/*.json for offline dev/tests."""

    def __init__(self, mock_dir: Path = _MOCK_DIR):
        self._dir = mock_dir

    def _load(self, name: str) -> list[dict]:
        path = self._dir / name
        if not path.exists():
            logger.warning("Mock ES fixture missing: %s", path)
            return []
        with open(path, encoding="utf-8") as f:
            return json.load(f)

    def top_talkers(self, limit: int = 10) -> list[dict]:
        return self._load("top_talkers.json")[:limit]

    def search_iocs(
        self, ips: list[str], domains: list[str], hashes: list[str]
    ) -> list[dict]:
        wanted = {("ips", v) for v in ips}
        wanted |= {("domains", v) for v in domains}
        wanted |= {("hashes", v) for v in hashes}
        hits = self._load("ioc_hits.json")
        return [h for h in hits if (h.get("ioc_type"), h.get("ioc")) in wanted]


# ── Live implementation ──────────────────────────────────────────────────


class LiveESClient:
    """Real cluster via elasticsearch-py. Imported lazily so mock mode has no dep."""

    def __init__(self):
        from elasticsearch import Elasticsearch  # lazy

        kwargs: dict = {"hosts": [settings.es_url]}
        if settings.es_api_key:
            kwargs["api_key"] = settings.es_api_key
        elif settings.es_username:
            kwargs["basic_auth"] = (settings.es_username, settings.es_password)
        self._es = Elasticsearch(**kwargs)

    def top_talkers(self, limit: int = 10) -> list[dict]:
        # Aggregate bytes by source IP over the flow indices (ECS: source.ip,
        # source.bytes). Adjust field names to your pipeline as needed.
        resp = self._es.search(
            index=settings.es_flow_index,
            size=0,
            aggs={
                "by_src": {
                    "terms": {"field": "source.ip", "size": limit},
                    "aggs": {
                        "bytes": {"sum": {"field": "source.bytes"}},
                        "peers": {"terms": {"field": "destination.ip", "size": 5}},
                    },
                }
            },
        )
        out = []
        for b in resp["aggregations"]["by_src"]["buckets"]:
            out.append(
                {
                    "ip": b["key"],
                    "bytes_total": int(b["bytes"]["value"] or 0),
                    "flows": b["doc_count"],
                    "peers": [p["key"] for p in b["peers"]["buckets"]],
                }
            )
        return out

    def search_iocs(
        self, ips: list[str], domains: list[str], hashes: list[str]
    ) -> list[dict]:
        # ECS terms across likely IOC fields. Kept intentionally simple; refine
        # per your schema (e.g. add threat.indicator.* fields).
        field_map = {
            "ips": ["source.ip", "destination.ip"],
            "domains": ["dns.question.name", "url.domain", "destination.domain"],
            "hashes": ["file.hash.sha256", "file.hash.md5", "file.hash.sha1"],
        }
        results: list[dict] = []
        for ioc_type, values in (("ips", ips), ("domains", domains), ("hashes", hashes)):
            for value in values:
                should = [{"term": {f: value}} for f in field_map[ioc_type]]
                resp = self._es.search(
                    index=settings.es_event_index,
                    size=0,
                    track_total_hits=True,
                    query={"bool": {"should": should, "minimum_should_match": 1}},
                    aggs={
                        "first": {"min": {"field": "@timestamp"}},
                        "last": {"max": {"field": "@timestamp"}},
                    },
                )
                count = resp["hits"]["total"]["value"]
                if count:
                    results.append(
                        {
                            "ioc": value,
                            "ioc_type": ioc_type,
                            "index": settings.es_event_index,
                            "count": count,
                            "first_seen": resp["aggregations"]["first"].get("value_as_string", ""),
                            "last_seen": resp["aggregations"]["last"].get("value_as_string", ""),
                        }
                    )
        return results


def get_es_client() -> ESClient:
    if settings.es_mode == "live":
        logger.info("ES client: live (%s)", settings.es_url)
        return LiveESClient()
    logger.info("ES client: mock")
    return MockESClient()
