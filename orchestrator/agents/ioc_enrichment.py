import logging
import os

from deepagents import create_deep_agent

from .tools.ioc_tools import lookup_domain, lookup_hash, lookup_ip

logger = logging.getLogger(__name__)

_MODEL = "anthropic:" + os.environ.get("DIRECT_MODEL", "claude-sonnet-4-6")

_SYSTEM_PROMPT = """You are a threat intelligence analyst. Your job is to investigate every IOC \
provided by calling the available lookup tools, then write a concise markdown threat intelligence report.

Process:
1. Call lookup_ip, lookup_domain, or lookup_hash for EVERY indicator provided — do not skip any.
2. After all lookups are complete, write your report. Use markdown formatting.

Report structure:
- **Verdict summary** — lead with counts: e.g. "3 of 5 IOCs are malicious"
- **Findings** — list each IOC with its reputation, category, and key details. \
  Severity emoji: 🔴 malicious  🟡 suspicious  🟢 clean  ⚪ unknown
- **Analyst Notes** — one or two sentences on patterns, clustering, or shared campaigns
- **Recommended Actions** — specific next steps ordered by urgency

Rules: max 400 words, no raw JSON in output."""

_agent = create_deep_agent(
    model=_MODEL,
    tools=[lookup_ip, lookup_domain, lookup_hash],
    system_prompt=_SYSTEM_PROMPT,
)


def enrich_iocs(ips: list[str], domains: list[str], hashes: list[str]) -> str:
    """Look up indicators of compromise against threat intelligence databases.

    Use this tool when the user provides IP addresses, domain names, or file hashes
    to check, or asks whether an indicator is malicious, suspicious, or known bad.

    Args:
        ips: IPv4 addresses to look up (e.g. ["198.51.100.10", "8.8.8.8"])
        domains: Domain names to look up (e.g. ["evildomain.xyz", "google.com"])
        hashes: MD5, SHA1, or SHA256 file hashes to look up

    Returns:
        Markdown threat intelligence report with reputation and findings for each IOC.
    """
    logger.info("enrich_iocs: ips=%d domains=%d hashes=%d", len(ips), len(domains), len(hashes))

    lines = []
    if ips:
        lines.append(f"IPs: {', '.join(ips)}")
    if domains:
        lines.append(f"Domains: {', '.join(domains)}")
    if hashes:
        lines.append(f"Hashes: {', '.join(hashes)}")
    question = "Look up these IOCs and report on their reputation:\n" + "\n".join(lines)

    result = _agent.invoke({"messages": [{"role": "user", "content": question}]})
    messages = result.get("messages", [])
    if not messages:
        return "IOC enrichment returned no results."
    last = messages[-1]
    report = last.content if hasattr(last, "content") else str(last)
    logger.info("enrich_iocs complete: report_len=%d", len(report))
    return report
