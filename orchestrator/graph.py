import logging
import re
from typing import TypedDict

from langgraph.graph import END, StateGraph

from .agents.intent_classifier import classify_intent
from .agents.ioc_enrichment import enrich_iocs
from .agents.router_config import analyze_router_config
from .agents.synthesis import synthesize_findings

logger = logging.getLogger(__name__)

CONFIDENCE_THRESHOLD = 0.40

# Cisco IOS keywords — any hit means the injected file is a router config
_IOS_KEYWORDS = {
    "interface ", "ip address ", "line vty", "line con ",
    "hostname ", "router ospf", "router eigrp", "router bgp",
    "ip route ", "access-list ", "ip access-list", "enable secret",
    "service password", "snmp-server", "logging buffered",
    "ntp server", "crypto isakmp", "spanning-tree",
}

# Pattern that matches plugin-injected file blocks:
# --- Contents of <name> ---
# <content>
# --- End of <name> ---
_INJECTION_RE = re.compile(
    r"--- Contents of .+? ---\n(.*?)\n--- End of .+? ---",
    re.DOTALL,
)


class HuntState(TypedDict):
    question: str
    intent: str
    confidence: float
    entities: dict
    agent_output: dict
    final_response: str


def _preprocess(state: HuntState) -> HuntState:
    """Extract vault-injected file blocks without an LLM call.

    If the message contains a --- Contents of X --- block with recognisable
    Cisco IOS keywords, pre-classify as router_config at 0.95 confidence and
    populate config_blob so the classifier can be skipped entirely.
    """
    match = _INJECTION_RE.search(state["question"])
    if not match:
        return state

    content = match.group(1).strip()
    content_lower = content.lower()

    if any(kw in content_lower for kw in _IOS_KEYWORDS):
        logger.info("Pre-processor: Cisco IOS config detected in injected block — bypassing classifier")
        return {
            **state,
            "intent": "router_config",
            "confidence": 0.95,
            "entities": {
                "ips": [],
                "domains": [],
                "hashes": [],
                "config_blob": content,
            },
        }

    logger.info("Pre-processor: injection block found but no IOS keywords — falling through to classifier")
    return state


def _clarify(state: HuntState) -> HuntState:
    return {
        **state,
        "final_response": (
            "I need a bit more context to help you. Could you clarify:\n\n"
            "- Are you analyzing a **Cisco IOS router or switch configuration**? "
            "If so, please paste the config snippet or use `@agent analyze [[filename]]`.\n"
            "- Are you looking up **indicators of compromise** (IP addresses, domains, file hashes)? "
            "If so, please list them.\n\n"
            f"_(Classified intent: `{state['intent']}`, confidence: {state['confidence']:.0%})_"
        ),
    }


def _route_preprocess(state: HuntState) -> str:
    """After pre-processing: skip the classifier if already confident."""
    if state["confidence"] >= CONFIDENCE_THRESHOLD and state["intent"] in ("router_config", "ioc_enrichment"):
        logger.info("Pre-processor confident (%.2f) — routing directly to %s", state["confidence"], state["intent"])
        return state["intent"]
    return "classify"


def _route_classify(state: HuntState) -> str:
    """After classifier: route to agent or clarify."""
    if state["confidence"] < CONFIDENCE_THRESHOLD or state["intent"] == "unknown":
        logger.info("Classifier low confidence (%.2f) or unknown — routing to clarify", state["confidence"])
        return "clarify"
    return state["intent"]


def _build_graph():
    workflow = StateGraph(HuntState)

    workflow.add_node("preprocess", _preprocess)
    workflow.add_node("classify", classify_intent)
    workflow.add_node("router_config", analyze_router_config)
    workflow.add_node("ioc_enrichment", enrich_iocs)
    workflow.add_node("clarify", _clarify)
    workflow.add_node("synthesize", synthesize_findings)

    workflow.set_entry_point("preprocess")

    workflow.add_conditional_edges(
        "preprocess",
        _route_preprocess,
        {
            "router_config": "router_config",
            "ioc_enrichment": "ioc_enrichment",
            "classify": "classify",
        },
    )

    workflow.add_conditional_edges(
        "classify",
        _route_classify,
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
