"""Top-level supervisor graph — the orchestrator entrypoint.

Owns a `StateGraph` over `HuntState` and the conversation checkpointer.

    supervisor ─(route)─┬─ chat ─────────────► generalist ─► END
                        └─ network/ti/both ──► network_stage ─► ti_stage
                                               ─► correlate ─► synthesize ─► END

The two branch stages run in isolation and contribute only their own artifacts;
`correlate` then joins them into ranked hypotheses and `synthesize` writes the
final report. The `chat` route preserves the original single-agent behavior for
simple IOC checks, device-config audits, and general questions.
"""

from __future__ import annotations

import logging

from deepagents import create_deep_agent
from langchain_core.messages import HumanMessage
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph

from .branches import network, threatintel
from .branches.network.router_config import analyze_router_config
from .branches.threatintel.ioc_enrich import enrich_iocs
from .correlate import correlate_node
from .llm import get_chat_model
from .llm_util import message_text
from .router import classify
from .state import Artifacts, HuntState
from .synthesis import synthesize_node

logger = logging.getLogger(__name__)

GENERALIST_PROMPT = """You are a threat hunter for a network security operations team. \
Your responses are displayed in an Obsidian markdown chat window — use markdown formatting.

## Tool guidance
- Call `enrich_iocs` when the user provides IP addresses, domain names, or file hashes to check, \
or asks whether an indicator is malicious, suspicious, or known bad.
- Call `analyze_router_config` when the user provides a Cisco IOS router or switch configuration — \
either pasted directly or inside a file injection block ("--- Contents of X ---" / "--- End of X ---"). \
Also call it when asked to audit, harden, or review a network device config.
- Call both tools when the question involves both IOCs and a router config, then correlate the findings.
- If the input is genuinely ambiguous — no config lines, no IOC indicators — ask one focused \
clarifying question rather than guessing.

## Report format
Structure every response as a markdown report:
1. **Executive Summary** (2-3 sentences)
2. **Findings** — grouped by severity, most critical first. \
Severity emoji: 🔴 critical  🟠 high  🟡 medium  🔵 low  ⚪ informational
3. **Recommended Actions** — bullet list, specific and ordered by urgency
4. **Risk Score** — if a numeric score is present in the data, display as `Risk: XX/100`

Additional rules:
- Max 500 words. Use headers, bold, and bullets for scannability.
- Never include raw JSON in the output.
- If tool results are empty or findings list is empty, say so plainly and suggest \
what additional information would help."""


# Built once; model comes from the provider factory (env-swappable to Ollama/Bedrock).
_generalist = create_deep_agent(
    model=get_chat_model("synthesis"),
    tools=[enrich_iocs, analyze_router_config],
    system_prompt=GENERALIST_PROMPT,
)


# ── Nodes ────────────────────────────────────────────────────────────────


def supervisor_node(state: HuntState) -> dict:
    route = classify(state.get("question", ""))
    logger.info("Supervisor: route=%s", route)
    return {"route": route}


def network_stage(state: HuntState) -> dict:
    if state.get("route") in ("network", "both"):
        return {"artifacts": network.run(state["question"]), "completed": ["network"]}
    return {}


def threatintel_stage(state: HuntState) -> dict:
    if state.get("route") in ("threatintel", "both"):
        return {"artifacts": threatintel.run(state["question"]), "completed": ["threatintel"]}
    return {}


def generalist_node(state: HuntState) -> dict:
    result = _generalist.invoke({"messages": state["messages"]})
    messages = result.get("messages", [])
    if not messages:
        return {"report": "No response generated."}
    final = messages[-1]
    report = message_text(final) if hasattr(final, "content") else str(final)
    return {"messages": [final], "report": report}


def _route_edge(state: HuntState) -> str:
    return "chat" if state.get("route") == "chat" else "pipeline"


def build_graph(checkpointer: MemorySaver | None = None):
    g = StateGraph(HuntState)
    g.add_node("supervisor", supervisor_node)
    g.add_node("generalist", generalist_node)
    g.add_node("network_stage", network_stage)
    g.add_node("threatintel_stage", threatintel_stage)
    g.add_node("correlate", correlate_node)
    g.add_node("synthesize", synthesize_node)

    g.add_edge(START, "supervisor")
    g.add_conditional_edges(
        "supervisor",
        _route_edge,
        {"chat": "generalist", "pipeline": "network_stage"},
    )
    g.add_edge("network_stage", "threatintel_stage")
    g.add_edge("threatintel_stage", "correlate")
    g.add_edge("correlate", "synthesize")
    g.add_edge("synthesize", END)
    g.add_edge("generalist", END)
    return g.compile(checkpointer=checkpointer or MemorySaver())


_app = build_graph()


def run_hunt(question: str, thread_id: str = "default") -> str:
    """Invoke the orchestrator for one turn and return the markdown report."""
    config = {"configurable": {"thread_id": thread_id}}
    result = _app.invoke(
        {"messages": [HumanMessage(question)], "question": question, "artifacts": Artifacts()},
        config=config,
    )
    return result.get("report") or "No response generated."
