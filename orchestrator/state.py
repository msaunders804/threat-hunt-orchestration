"""Shared graph state and artifact models for the hunt orchestrator.

`HuntState` is the single object threaded through the supervisor graph and both
branch subgraphs. Nodes read what they need and merge their outputs back in.
Artifacts are typed (Pydantic) so downstream nodes — and the final synthesis —
have a stable contract regardless of which branch produced them.
"""

from __future__ import annotations

import operator
from typing import Annotated, Any, Literal, Optional

from langchain_core.messages import AnyMessage
from langgraph.graph.message import add_messages
from pydantic import BaseModel, Field
from typing_extensions import TypedDict

Branch = Literal["network", "threatintel", "both", "clarify"]


# ── Artifact models ──────────────────────────────────────────────────────


class Service(BaseModel):
    port: int
    protocol: str = "tcp"
    name: str = ""
    product: str = ""
    version: str = ""


class Host(BaseModel):
    ip: str
    hostname: str = ""
    os: str = ""
    os_accuracy: Optional[int] = None
    status: str = "up"
    services: list[Service] = Field(default_factory=list)
    # Free-form role guess (e.g. "web server", "domain controller").
    role: str = ""


class TrafficStat(BaseModel):
    ip: str
    bytes_total: int = 0
    flows: int = 0
    peers: list[str] = Field(default_factory=list)


class VulnFinding(BaseModel):
    ip: str
    severity: Literal["critical", "high", "medium", "low", "informational"]
    title: str
    description: str = ""
    evidence: str = ""
    references: list[str] = Field(default_factory=list)


class IOCResult(BaseModel):
    ioc: str
    ioc_type: Literal["ips", "domains", "hashes"]
    found: bool = False
    reputation: str = "unknown"
    category: str = ""
    source: str = "local"


class SigmaRule(BaseModel):
    technique: str  # ATT&CK T-code, e.g. "T1059.001"
    title: str
    path: str = ""  # where the YAML was written
    yaml: str = ""
    backend_query: str = ""  # optional compiled ES query


class Hypothesis(BaseModel):
    statement: str
    confidence: Literal["high", "medium", "low"] = "medium"
    supporting: list[str] = Field(default_factory=list)


class Artifacts(BaseModel):
    """Accumulated outputs from every branch, correlated by the synthesis step."""

    hosts: list[Host] = Field(default_factory=list)
    network_map_path: str = ""
    traffic: list[TrafficStat] = Field(default_factory=list)
    vulns: list[VulnFinding] = Field(default_factory=list)
    iocs: list[IOCResult] = Field(default_factory=list)
    sigma_rules: list[SigmaRule] = Field(default_factory=list)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    # Raw per-agent JSON blobs, kept for the synthesis prompt / debugging.
    evidence: dict[str, Any] = Field(default_factory=dict)


def _merge_artifacts(left: Artifacts | None, right: Artifacts | None) -> Artifacts:
    """Reducer: concatenate list fields and merge evidence dicts across nodes."""
    if left is None:
        return right or Artifacts()
    if right is None:
        return left
    return Artifacts(
        hosts=left.hosts + right.hosts,
        network_map_path=right.network_map_path or left.network_map_path,
        traffic=left.traffic + right.traffic,
        vulns=left.vulns + right.vulns,
        iocs=left.iocs + right.iocs,
        sigma_rules=left.sigma_rules + right.sigma_rules,
        hypotheses=left.hypotheses + right.hypotheses,
        evidence={**left.evidence, **right.evidence},
    )


# ── Graph state ──────────────────────────────────────────────────────────


class HuntState(TypedDict, total=False):
    # Conversation history (supports multi-turn via the checkpointer).
    messages: Annotated[list[AnyMessage], add_messages]
    # The raw user question / pasted payload for this turn.
    question: str
    # Supervisor routing decision for this turn.
    route: Branch
    # Accumulated, typed outputs from all branches (custom merge reducer).
    artifacts: Annotated[Artifacts, _merge_artifacts]
    # Final markdown report returned to the caller.
    report: str
    # Names of branches that have already run this turn (loop guard).
    completed: Annotated[list[str], operator.add]
