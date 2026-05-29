import logging
import os

from deepagents import create_deep_agent

from .agents.ioc_enrichment import enrich_iocs
from .agents.router_config import analyze_router_config

logger = logging.getLogger(__name__)

# deepagents uses "provider:model-id" strings.
# Bedrock support depends on whether your deepagents build includes langchain-aws;
# for Bedrock, set INFERENCE_PROVIDER=bedrock and override _MODEL below manually.
_MODEL = "anthropic:" + os.environ.get("DIRECT_MODEL", "claude-sonnet-4-6")

SYSTEM_PROMPT = """You are a threat hunter for a network security operations team. \
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
- For IOC results: lead with verdict counts (e.g. "3 of 5 IOCs are malicious"), \
then list each IOC with its reputation and threat category.
- For router config results: lead with the risk score and count of critical/high findings, \
then summarize each finding in one bullet.
- If tool results are empty or findings list is empty, say so plainly and suggest \
what additional information would help."""

_agent = create_deep_agent(
    model=_MODEL,
    tools=[enrich_iocs, analyze_router_config],
    system_prompt=SYSTEM_PROMPT,
)


def run_hunt(question: str) -> str:
    result = _agent.invoke({"messages": [{"role": "user", "content": question}]})
    messages = result.get("messages", [])
    if not messages:
        return "No response generated."
    last = messages[-1]
    return last.content if hasattr(last, "content") else str(last)
