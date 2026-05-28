import json
import logging
import re

from ..client import _client, _model


def _strip_fences(text: str) -> str:
    text = text.strip()
    text = re.sub(r'^```(?:json)?\s*\n?', '', text, flags=re.IGNORECASE)
    text = re.sub(r'\n?```\s*$', '', text)
    return text.strip()

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a threat hunting query classifier for a network security operations team.

Analyze the input and classify the primary intent. Be decisive — prefer routing to an agent over asking for clarification.

Supported intents:
- "router_config": Analyze a Cisco IOS router or switch configuration. Trigger on ANY of:
  - Config lines present (interface, ip address, line vty, access-list, hostname, router ospf, enable secret, snmp-server, etc.)
  - A file block injected between "--- Contents of X ---" and "--- End of X ---" markers
  - Explicit request to audit, harden, or check a network device config
- "ioc_enrichment": Look up indicators of compromise. Trigger on ANY of:
  - IPv4 addresses listed for assessment
  - Domain names listed for reputation check
  - MD5 / SHA1 / SHA256 hashes listed
  - Explicit "is X malicious / safe / known bad" questions about an IP, domain, or hash
- "unknown": Use ONLY when input contains neither config lines nor IOC indicators AND the request is genuinely ambiguous.

File injection format: the Obsidian plugin wraps vault file contents like this:
  [[filename]]
  --- Contents of filename ---
  <file contents here>
  --- End of filename ---
If you see this pattern, extract the contents as config_blob and classify based on what the file contains.

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
  "reasoning": "one sentence"
}

Confidence guide:
- 0.90–1.00: explicit config lines or explicit IOC list present — no ambiguity
- 0.70–0.89: clear intent from phrasing even without raw data
- 0.40–0.69: reasonable inference — route to the agent rather than asking for clarification
- < 0.40: genuinely unclear — use "unknown"

For config_blob: copy the full content from inside "--- Contents of X ---" blocks, or the raw config text if pasted directly."""


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

    raw = _strip_fences(response.content[0].text)

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
