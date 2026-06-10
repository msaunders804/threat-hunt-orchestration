import logging
import os

from deepagents import create_deep_agent

from .tools.config_tools import check_ios_eos, get_hardening_guidance, lookup_cve

logger = logging.getLogger(__name__)

_MODEL = "anthropic:" + os.environ.get("DIRECT_MODEL", "claude-sonnet-4-6")

_SYSTEM_PROMPT = """You are a senior network security engineer conducting a Cisco IOS security audit. \
Your responses are displayed in an Obsidian markdown window — use markdown formatting.

Process — follow these steps before writing your report:
1. Check the IOS version: call check_ios_eos with the version line you find in the config.
2. Identify security issues across: ACLs, management plane, routing protocols, service hardening, \
logging, and encryption.
3. For each significant finding, enrich it:
   - Call lookup_cve for known-vulnerable configurations (Smart Install enabled → CVE-2018-0171; \
HTTP server enabled → CVE-2023-20198; SNMP v1/v2c → CVE-2017-6627).
   - Call get_hardening_guidance for exact remediation IOS commands (topics: snmp, telnet, acl, \
bgp, logging, passwords, cdp, vty).
4. After all tool calls are complete, write your report.

Report structure:
1. **Executive Summary** — 2-3 sentences including IOS version status and overall risk
2. **Findings** — grouped by severity, most critical first. \
   Severity emoji: 🔴 critical  🟠 high  🟡 medium  🔵 low  ⚪ informational. \
   Include CVE if applicable.
3. **Recommended Actions** — specific IOS commands ordered by urgency
4. **Risk Score** — display as `Risk: XX/100`

Rules: max 500 words, no raw JSON in output."""

_agent = create_deep_agent(
    model=_MODEL,
    tools=[check_ios_eos, lookup_cve, get_hardening_guidance],
    system_prompt=_SYSTEM_PROMPT,
)


def analyze_router_config(router_config: str) -> str:
    """Analyze a Cisco IOS router or switch configuration for security vulnerabilities.

    Use this tool when the user provides a Cisco IOS config — either pasted directly
    or inside a file injection block ("--- Contents of X ---" / "--- End of X ---").
    Also use when asked to audit, harden, or review a network device configuration.

    Args:
        router_config: Raw Cisco IOS configuration text to analyze.

    Returns:
        Markdown security audit report with findings, CVEs, risk score, and remediation steps.
    """
    logger.info("analyze_router_config: config_len=%d", len(router_config))
    result = _agent.invoke({"messages": [{"role": "user", "content": router_config}]})
    messages = result.get("messages", [])
    if not messages:
        return "Router config analysis returned no results."
    last = messages[-1]
    report = last.content if hasattr(last, "content") else str(last)
    logger.info("analyze_router_config complete: report_len=%d", len(report))
    return report
