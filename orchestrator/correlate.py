"""Cross-branch correlation → ranked hunt hypotheses.

The value of running both branches is the intersection: an internal host that is
(a) talking to a known-malicious indicator, (b) a heavy talker, and/or (c)
vulnerable is a far stronger lead than any single signal. This node is
deterministic — it joins the typed artifacts the branches already produced — so
the reasoning is transparent and reproducible.
"""

from __future__ import annotations

import logging

from .state import Artifacts, Hypothesis, HuntState

logger = logging.getLogger(__name__)

_BAD = {"malicious", "suspicious"}


def _confidence(signals: int) -> str:
    return "high" if signals >= 3 else "medium" if signals == 2 else "low"


def correlate(art: Artifacts) -> list[Hypothesis]:
    bad_iocs = {i.ioc for i in art.iocs if i.reputation in _BAD}
    talkers = {t.ip: t for t in art.traffic}
    vuln_by_ip: dict[str, list] = {}
    for v in art.vulns:
        vuln_by_ip.setdefault(v.ip, []).append(v)

    # internal host -> set of malicious indicators it contacted (from ES hits)
    contact: dict[str, set[str]] = {}
    for hit in art.evidence.get("ioc_es_hits", []) or []:
        if hit.get("ioc") in bad_iocs:
            for host in hit.get("internal_peers", []) or []:
                contact.setdefault(host, set()).add(hit["ioc"])
    # also use network-map peers: talker -> peers that are bad IOCs
    for ip, t in talkers.items():
        for peer in t.peers:
            if peer in bad_iocs:
                contact.setdefault(ip, set()).add(peer)

    hypotheses: list[Hypothesis] = []
    for host in sorted(set(contact) | set(vuln_by_ip)):
        supporting: list[str] = []
        signals = 0
        if host in contact:
            signals += 1
            supporting.append(
                f"Communicates with malicious indicator(s): {', '.join(sorted(contact[host]))}"
            )
        if host in talkers:
            signals += 1
            t = talkers[host]
            supporting.append(f"High traffic volume ({t.bytes_total:,} bytes, {t.flows} flows)")
        if host in vuln_by_ip:
            signals += 1
            titles = ", ".join(v.title for v in vuln_by_ip[host][:3])
            supporting.append(f"Vulnerable: {titles}")

        # Only surface hosts with a cross-signal (contact-with-bad, or vuln+talker).
        if host in contact or (host in vuln_by_ip and host in talkers):
            hypotheses.append(
                Hypothesis(
                    statement=f"Host {host} may be compromised or actively targeted.",
                    confidence=_confidence(signals),
                    supporting=supporting,
                )
            )

    # Strongest leads first.
    order = {"high": 0, "medium": 1, "low": 2}
    hypotheses.sort(key=lambda h: order[h.confidence])
    logger.info("Correlation: %d hypotheses", len(hypotheses))
    return hypotheses


def correlate_node(state: HuntState) -> dict:
    art = state.get("artifacts") or Artifacts()
    return {"artifacts": Artifacts(hypotheses=correlate(art)), "completed": ["correlate"]}
