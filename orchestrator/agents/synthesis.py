import json
import logging

from ..client import _client, _model

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a cybersecurity analyst writing concise, actionable threat hunt reports for a security operations team. Reports are displayed in an Obsidian markdown chat window — use markdown formatting.

Structure every report as:
1. **Executive Summary** (2-3 sentences)
2. Findings — grouped by severity, most critical first. Use severity emoji: 🔴 critical, 🟠 high, 🟡 medium, 🔵 low, ⚪ informational
3. **Recommended Actions** — bullet list, specific and ordered by urgency
4. **Risk Score** — if a numeric score is present in the data, display it as `Risk: XX/100`

Rules:
- Max 500 words. Use headers, bold text, and bullets for scannability.
- Never include raw JSON in the output.
- For IOC enrichment results: lead with the verdict counts (e.g., "3 of 5 IOCs are malicious"), then list each IOC with its category and severity.
- For router config results: lead with the risk score and count of critical/high findings, then summarize each finding in one bullet.
- If findings list is empty, say so plainly and suggest what information would help (paste a config, or list specific IOCs)."""


def synthesize_findings(state: dict) -> dict:
    intent = state.get("intent", "unknown")
    agent_output = state.get("agent_output", {})
    question = state.get("question", "")

    context = (
        f"Intent: {intent}\n"
        f"Original question: {question}\n\n"
        f"Agent findings (JSON):\n{json.dumps(agent_output, indent=2)}"
    )

    logger.info("Synthesizing findings for intent=%s", intent)

    response = _client.messages.create(
        model=_model,
        max_tokens=1024,
        system=[
            {
                "type": "text",
                "text": SYSTEM_PROMPT,
                "cache_control": {"type": "ephemeral"},
            }
        ],
        messages=[{"role": "user", "content": context}],
    )

    final_response = response.content[0].text.strip()

    usage = getattr(response, "usage", None)
    cache_read = getattr(usage, "cache_read_input_tokens", 0)
    logger.info("Synthesis complete: len=%d cache_read=%d", len(final_response), cache_read)

    return {**state, "final_response": final_response}
