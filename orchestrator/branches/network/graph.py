"""Network Analysis branch subgraph.

Pipeline over the shared `HuntState`:

    parse_scan -> traffic -> network_map -> vuln_triage

Each node contributes typed artifacts (hosts, traffic, network_map_path, vulns)
that are merged into `state["artifacts"]` by the reducer in `state.py` and later
correlated/synthesized. The router-config auditor remains available as a tool on
the generalist agent and can be invoked directly via `analyze_router_config`.
"""

from __future__ import annotations

import logging

from langgraph.graph import END, START, StateGraph

from ...state import Artifacts, HuntState
from .es_traffic import top_talkers
from .network_map import write_network_map
from .parse_scan import parse_scan
from .vuln_triage import triage_hosts

logger = logging.getLogger(__name__)


def parse_node(state: HuntState) -> dict:
    hosts = parse_scan(state.get("question", ""))
    return {"artifacts": Artifacts(hosts=hosts), "completed": ["network:parse"]}


def traffic_node(state: HuntState) -> dict:
    stats = top_talkers(limit=10)
    return {"artifacts": Artifacts(traffic=stats), "completed": ["network:traffic"]}


def map_node(state: HuntState) -> dict:
    art = state.get("artifacts") or Artifacts()
    path = write_network_map(art.hosts, art.traffic)
    return {
        "artifacts": Artifacts(network_map_path=path),
        "completed": ["network:map"],
    }


def vuln_node(state: HuntState) -> dict:
    art = state.get("artifacts") or Artifacts()
    findings = triage_hosts(art.hosts)
    return {"artifacts": Artifacts(vulns=findings), "completed": ["network:vuln"]}


def build_network_branch():
    g = StateGraph(HuntState)
    g.add_node("net_parse", parse_node)
    g.add_node("net_traffic", traffic_node)
    g.add_node("net_map", map_node)
    g.add_node("net_vuln", vuln_node)
    g.add_edge(START, "net_parse")
    g.add_edge("net_parse", "net_traffic")
    g.add_edge("net_traffic", "net_map")
    g.add_edge("net_map", "net_vuln")
    g.add_edge("net_vuln", END)
    return g.compile()


network_branch = build_network_branch()


def run(question: str) -> Artifacts:
    """Execute the network branch in isolation; returns only this branch's artifacts.

    Running from an empty Artifacts means the subgraph's output equals the branch's
    own contribution, so the supervisor can merge it once without double-counting.
    """
    result = network_branch.invoke({"question": question, "artifacts": Artifacts()})
    return result.get("artifacts") or Artifacts()
