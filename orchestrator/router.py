"""Supervisor routing logic.

Decides which branch(es) a turn needs. Deterministic signals resolve the common,
unambiguous cases for free (and keep the system working offline / on a small
router SLM); only genuinely ambiguous input falls through to the LLM router.

Routes:
  * "network"     — scan data or network-map/traffic/vuln request
  * "threatintel" — ATT&CK T-codes / Sigma request (IOC-only hunts also fit here)
  * "both"        — signals for both
  * "chat"        — simple IOC check, router-config paste, or general Q&A →
                    handled by the generalist agent (parity with prior behavior)
"""

from __future__ import annotations

import logging
import re

from .branches.threatintel.attack_mapper import extract_tcodes
from .branches.threatintel.ioc_search import extract_indicators
from .llm import structured
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

_SCAN_SIGNALS = re.compile(
    r"<nmaprun|Nmap scan report for|\bis alive\b|\bfping\b|\bnmap\b", re.IGNORECASE
)
_NET_REQUEST = re.compile(
    r"network map|top talker|top-talker|vulnerab|scan result|obsidian graph", re.IGNORECASE
)
_SIGMA_REQUEST = re.compile(r"sigma|detection rule|kill chain|scheme of maneuver", re.IGNORECASE)
_CONFIG_SIGNAL = re.compile(r"interface \S|line vty|transport input|access-list", re.IGNORECASE)


class RouteDecision(BaseModel):
    route: str = Field(description="one of: network, threatintel, both, chat")


LLM_PROMPT = """Classify this threat-hunt request into exactly one route:
- network: contains nmap/fping scan output, or asks for a network map, top-talkers, or vulnerability triage
- threatintel: provides ATT&CK technique IDs / a kill chain to build Sigma rules for, or an IOC hunt over log data
- both: clearly needs network analysis AND threat intel
- chat: a simple indicator reputation check, a pasted device config to audit, or a general question

Answer with just the route."""


def _heuristic(question: str) -> str | None:
    has_scan = bool(_SCAN_SIGNALS.search(question) or _NET_REQUEST.search(question))
    has_tcodes = bool(extract_tcodes(question))
    has_sigma = bool(_SIGMA_REQUEST.search(question))
    ti = has_tcodes or has_sigma

    if has_scan and ti:
        return "both"
    if has_scan:
        return "network"
    if ti:
        return "threatintel"
    # A pasted device config is a generalist (router-config) job, not a branch.
    if _CONFIG_SIGNAL.search(question):
        return "chat"
    return None


def classify(question: str) -> str:
    heur = _heuristic(question)
    if heur:
        logger.info("Router: heuristic -> %s", heur)
        return heur

    # Ambiguous: if there are indicators but nothing else, treat as a chat IOC check.
    ind = extract_indicators(question)
    if any(ind.values()) and len(question) < 400:
        logger.info("Router: indicators-only -> chat")
        return "chat"

    try:
        decision: RouteDecision = structured("router", RouteDecision).invoke(
            [{"role": "system", "content": LLM_PROMPT}, {"role": "user", "content": question}]
        )
        route = decision.route.strip().lower()
        if route in {"network", "threatintel", "both", "chat"}:
            logger.info("Router: llm -> %s", route)
            return route
    except Exception:  # noqa: BLE001
        logger.exception("Router LLM failed; defaulting to chat")
    return "chat"
