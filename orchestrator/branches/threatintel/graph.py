"""Threat Intelligence branch subgraph.

Two capabilities over the shared `HuntState`, run in sequence:

    ioc_hunt -> sigma_detect

  * ioc_hunt   — extract indicators from the analyst input, enrich reputation
                 (local + optional external), and search ES for where they appear.
  * sigma_detect — extract ATT&CK T-codes / kill-chain narrative, resolve them,
                 author Sigma rules, and compile + write them to the vault.

Both write typed artifacts (iocs, sigma_rules) merged into `state["artifacts"]`.
"""

from __future__ import annotations

import logging

from langgraph.graph import END, START, StateGraph

from ...state import Artifacts, HuntState
from .attack_mapper import extract_tcodes, resolve
from .ioc_enrich import enrich
from .ioc_search import extract_indicators, search_environment
from .sigma_author import author_rules
from .sigma_compile import compile_and_write

logger = logging.getLogger(__name__)


def ioc_hunt_node(state: HuntState) -> dict:
    question = state.get("question", "")
    indicators = extract_indicators(question)
    iocs = enrich(indicators["ips"], indicators["domains"], indicators["hashes"])
    hits = search_environment(indicators["ips"], indicators["domains"], indicators["hashes"])
    return {
        "artifacts": Artifacts(iocs=iocs, evidence={"ioc_es_hits": hits}),
        "completed": ["ti:ioc"],
    }


def sigma_detect_node(state: HuntState) -> dict:
    question = state.get("question", "")
    tcodes = extract_tcodes(question)
    if not tcodes:
        return {"completed": ["ti:sigma"]}
    techniques = resolve(tcodes)
    rules = author_rules(techniques, narrative=question)
    rules = compile_and_write(rules)
    return {"artifacts": Artifacts(sigma_rules=rules), "completed": ["ti:sigma"]}


def build_threatintel_branch():
    g = StateGraph(HuntState)
    g.add_node("ti_ioc", ioc_hunt_node)
    g.add_node("ti_sigma", sigma_detect_node)
    g.add_edge(START, "ti_ioc")
    g.add_edge("ti_ioc", "ti_sigma")
    g.add_edge("ti_sigma", END)
    return g.compile()


threatintel_branch = build_threatintel_branch()


def run(question: str) -> Artifacts:
    """Execute the threat-intel branch in isolation; returns only this branch's artifacts."""
    result = threatintel_branch.invoke({"question": question, "artifacts": Artifacts()})
    return result.get("artifacts") or Artifacts()
