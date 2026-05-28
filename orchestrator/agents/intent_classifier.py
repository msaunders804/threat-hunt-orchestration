import json
import logging

from ..client import _client, _model

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a threat hunting query classifier for a network security operations team.

Analyze the user's natural language question and classify the primary intent, extract entities, and report confidence.

Supported intents:
- "router_config": The user wants to analyze a Cisco IOS router or switch configuration for security vulnerabilities, misconfigurations, or embedded IOCs. Triggered when the message contains router/switch config lines (interface, ip access-list, line vty, etc.) or explicitly asks about network device security.
- "ioc_enrichment": The user wants to assess indicators of compromise — IP addresses, domain names, or file hashes (MD5/SHA1/SHA256). Triggered when the message lists IPs, domains, or hash strings to look up.
- "unknown": Intent does not clearly match either supported type or there is insufficient context to act.

Return ONLY valid JSON — no prose, no markdown fences:
{
  "intent": "router_config|ioc_enrichment|unknown",
  "confidence": 0.0,
  "entities": {
    "ips": [],
    "domains": [],
    "hashes": [],
    "config_blob": null
  },
  "reasoning": "one sentence explaining the classification"
}

Rules:
- confidence >= 0.85 means high certainty; 0.60–0.84 means plausible; < 0.60 means unclear
- config_blob: copy the full router configuration text verbatim if the user pasted one
- Extract every IP address, domain, and hash string present even if embedded in sentences
- If the user pastes what looks like a Cisco IOS config, always classify as router_config regardless of phrasing"""


def classify_intent(state: dict) -> dict:
    question = state["question"]
    logger.info("Classifying intent (question_len=%d)", len(question))

    response = _client.messages.create(
        model=_model,
        max_tokens=512,
        system=[
            {
                "type": "text",
                "text": SYSTEM_PROMPT,
                "cache_control": {"type": "ephemeral"},
            }
        ],
        messages=[{"role": "user", "content": question}],
    )

    raw = response.content[0].text.strip()

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("Intent classifier returned non-JSON; defaulting to unknown. raw=%s", raw[:200])
        parsed = {
            "intent": "unknown",
            "confidence": 0.0,
            "entities": {"ips": [], "domains": [], "hashes": [], "config_blob": None},
            "reasoning": "parse error",
        }

    usage = getattr(response, "usage", None)
    cache_read = getattr(usage, "cache_read_input_tokens", 0)
    logger.info(
        "intent=%s confidence=%.2f cache_read=%d",
        parsed.get("intent"),
        float(parsed.get("confidence", 0.0)),
        cache_read,
    )

    return {
        **state,
        "intent": parsed.get("intent", "unknown"),
        "confidence": float(parsed.get("confidence", 0.0)),
        "entities": parsed.get("entities", {"ips": [], "domains": [], "hashes": [], "config_blob": None}),
    }
