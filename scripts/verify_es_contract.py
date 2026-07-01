"""Verify a live Elasticsearch cluster satisfies the orchestrator's field contract.

Runs the SAME queries LiveESClient uses and prints what comes back, so you can
confirm your Beats/Zeek field mappings line up before running a full hunt.

Usage (from repo root, with .env pointing at the live cluster):
    ES_MODE=live ES_URL=http://mini-pc:9200 ES_USERNAME=elastic ES_PASSWORD=... \
        python scripts/verify_es_contract.py
"""

from __future__ import annotations

import sys

from dotenv import load_dotenv

load_dotenv()

from orchestrator.config import settings  # noqa: E402
from orchestrator.services.elasticsearch import get_es_client  # noqa: E402


def main() -> int:
    print(f"ES mode : {settings.es_mode}")
    print(f"ES url  : {settings.es_url}")
    print(f"flow idx: {settings.es_flow_index}")
    print(f"evt idx : {settings.es_event_index}\n")

    if settings.es_mode != "live":
        print("WARNING: ES_MODE is not 'live' — you are testing the mock client.\n")

    client = get_es_client()

    print("── top_talkers(limit=5) ─────────────────────────────")
    try:
        talkers = client.top_talkers(limit=5)
        if not talkers:
            print("  (no results — check ES_FLOW_INDEX has flow docs with source.bytes)")
        for t in talkers:
            print(f"  {t['ip']:16} bytes={t['bytes_total']:>14,} flows={t['flows']:>6} peers={t['peers']}")
    except Exception as exc:  # noqa: BLE001
        print(f"  ERROR: {exc}")
        print("  → check auth, ES_URL reachability, and that source.ip/source.bytes exist")

    print("\n── search_iocs (sample indicators) ──────────────────")
    # Swap these for indicators you know exist in your data.
    ips = ["8.8.8.8"]
    domains = ["google.com"]
    hashes: list[str] = []
    try:
        hits = client.search_iocs(ips, domains, hashes)
        if not hits:
            print(f"  (no hits for {ips + domains} — expected if those aren't in your logs)")
        for h in hits:
            print(f"  {h['ioc']:24} type={h['ioc_type']:8} count={h['count']} "
                  f"[{h.get('first_seen','')} .. {h.get('last_seen','')}]")
    except Exception as exc:  # noqa: BLE001
        print(f"  ERROR: {exc}")
        print("  → check @timestamp and the dns.question.name / file.hash.* fields exist")

    print("\nDone. Empty results are fine if the data simply isn't there yet;")
    print("errors indicate an auth, connectivity, or field-mapping mismatch.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
