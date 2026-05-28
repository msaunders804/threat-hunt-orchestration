import logging
from typing import TypedDict

from langgraph.graph import END, StateGraph

from .agents.intent_classifier import classify_intent
from .agents.ioc_enrichment import enrich_iocs
from .agents.router_config import analyze_router_config
from .agents.synthesis import synthesize_findings

logger = logging.getLogger(__name__)

CONFIDENCE_THRESHOLD = 0.60


class HuntState(TypedDict):
    question: str
    intent: str
    confidence: float
    entities: dict
    agent_output: dict
    final_response: str


def _clarify(state: HuntState) -> HuntState:
    return {
        **state,
        "final_response": (
            "I need a bit more context to help you. Could you clarify:\n\n"
            "- Are you analyzing a **Cisco IOS router or switch configuration**? "
            "If so, please paste the config snippet.\n"
            "- Are you looking up **indicators of compromise** (IP addresses, domains, file hashes)? "
            "If so, please list them.\n\n"
            f"_(Classified intent: `{state['intent']}`, confidence: {state['confidence']:.0%})_"
        ),
    }


def _route(state: HuntState) -> str:
    if state["confidence"] < CONFIDENCE_THRESHOLD or state["intent"] == "unknown":
        logger.info("Low confidence (%.2f) or unknown intent — routing to clarify", state["confidence"])
        return "clarify"
    return state["intent"]


def _build_graph():
    workflow = StateGraph(HuntState)

    workflow.add_node("classify", classify_intent)
    workflow.add_node("router_config", analyze_router_config)
    workflow.add_node("ioc_enrichment", enrich_iocs)
    workflow.add_node("clarify", _clarify)
    workflow.add_node("synthesize", synthesize_findings)

    workflow.set_entry_point("classify")

    workflow.add_conditional_edges(
        "classify",
        _route,
        {
            "router_config": "router_config",
            "ioc_enrichment": "ioc_enrichment",
            "clarify": "clarify",
        },
    )

    workflow.add_edge("router_config", "synthesize")
    workflow.add_edge("ioc_enrichment", "synthesize")
    workflow.add_edge("clarify", END)
    workflow.add_edge("synthesize", END)

    return workflow.compile()


_graph = _build_graph()

_INITIAL_STATE: HuntState = {
    "question": "",
    "intent": "",
    "confidence": 0.0,
    "entities": {},
    "agent_output": {},
    "final_response": "",
}


def run_hunt(question: str) -> str:
    result = _graph.invoke({**_INITIAL_STATE, "question": question})
    return result["final_response"]
