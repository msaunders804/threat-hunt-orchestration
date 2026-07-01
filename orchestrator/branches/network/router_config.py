import json
import logging
import re

from ..client import _client, _model

logger = logging.getLogger(__name__)


def _strip_fences(text: str) -> str:
    text = text.strip()
    text = re.sub(r'^```(?:json)?\s*\n?', '', text, flags=re.IGNORECASE)
    text = re.sub(r'\n?```\s*$', '', text)
    return text.strip()


SYSTEM_PROMPT = """You are a senior network security engineer and threat hunter specializing in Cisco IOS device hardening, configuration auditing, and post-compromise analysis.

Analyze the provided Cisco IOS router or switch configuration for security issues across these categories:

1. ACL Security — missing implicit deny logging, overly permissive permit any, missing inbound ACLs on external interfaces, anti-spoofing (RFC 1918 blocking on WAN), uRPF
2. Management Plane — Telnet enabled (vs SSH), no VTY access-class, SNMP v1/v2c with guessable community strings, HTTP/HTTPS server enabled unnecessarily, no console exec-timeout, missing login block-for
3. Routing Protocol Security — OSPF/EIGRP/BGP without MD5 or SHA key-chain authentication, passive-interface not applied to user-facing or stub interfaces, no route filtering, no max-prefix limits on BGP peers
4. Service Hardening — CDP enabled on external interfaces, ip source-route enabled, directed broadcasts not disabled, finger service, BOOTP server, small TCP/UDP servers, proxy ARP on WAN interfaces
5. Logging & Audit — no syslog server configured, buffered logging size too small, no service timestamps, no logging sequence-numbers, no login on-failure logging
6. Encryption & Passwords — service password-encryption missing, type 0 or type 7 passwords present (require type 8 scrypt or type 9 bcrypt), weak or default enable secret, no SSH v2 explicit

Return ONLY valid JSON — no prose, no markdown fences, no code blocks:
{
  "findings": [
    {
      "category": "acl|routing|mgmt_plane|hardening|logging|encryption",
      "severity": "critical|high|medium|low|informational",
      "title": "concise finding title",
      "description": "what the problem is and why it matters operationally",
      "affected_config": "the exact config line(s) involved",
      "recommendation": "specific IOS commands to remediate"
    }
  ],
  "risk_score": 0,
  "summary": "2-3 sentence overall assessment",
  "immediate_actions": ["highest-priority remediation step", "second step"]
}

Severity guide:
- critical: direct path to RCE, credential theft, or full device compromise
- high: significant exposure enabling lateral movement or persistence
- medium: weakens defense-in-depth or enables reconnaissance
- low: best-practice deviation with limited direct impact
- informational: observation with no immediate risk

If no configuration text is present in the input, return findings: [] and note the absence in summary."""

_FEW_SHOT: list[dict] = [
    {
        "role": "user",
        "content": (
            "interface GigabitEthernet0/0\n"
            " ip address 203.0.113.1 255.255.255.0\n"
            " no shutdown\n"
            "line vty 0 4\n"
            " transport input telnet\n"
            " login local"
        ),
    },
    {
        "role": "assistant",
        "content": json.dumps(
            {
                "findings": [
                    {
                        "category": "mgmt_plane",
                        "severity": "critical",
                        "title": "Telnet enabled on VTY lines",
                        "description": (
                            "VTY lines accept Telnet, transmitting credentials and session content in plaintext. "
                            "A passive observer on the same path can capture the enable password and full session."
                        ),
                        "affected_config": "transport input telnet",
                        "recommendation": "line vty 0 4\n transport input ssh\nip ssh version 2",
                    },
                    {
                        "category": "mgmt_plane",
                        "severity": "high",
                        "title": "No ACL restricting VTY access",
                        "description": (
                            "Without an access-class on VTY lines, management login attempts are reachable "
                            "from any IP. Combined with Telnet, this maximises the attack surface."
                        ),
                        "affected_config": "line vty 0 4  (no access-class configured)",
                        "recommendation": (
                            "ip access-list standard MGMT-ACL\n"
                            " permit 10.0.0.0 0.255.255.255\n"
                            " deny any log\n"
                            "line vty 0 4\n"
                            " access-class MGMT-ACL in"
                        ),
                    },
                ],
                "risk_score": 82,
                "summary": (
                    "Management access is exposed via plaintext Telnet with no source-IP restriction. "
                    "An attacker on the same network segment or transit path can capture credentials silently. "
                    "Replacing Telnet with SSH and locking VTY to trusted subnets eliminates both vectors."
                ),
                "immediate_actions": [
                    "line vty 0 4 / transport input ssh — disable Telnet immediately",
                    "Apply access-class restricting VTY to trusted admin subnets",
                ],
            },
            indent=None,
        ),
    },
]


def analyze_router_config(config_blob: str) -> str:
    """Analyze a Cisco IOS router or switch configuration for security vulnerabilities.

    Use this tool when the user provides a Cisco IOS configuration — either pasted directly
    or inside a file injection block marked with '--- Contents of X ---' / '--- End of X ---'.
    Also use when the user asks to audit, harden, or review a network device config.

    Args:
        config_blob: The full Cisco IOS configuration text to analyze
    """
    logger.info("Analyzing router config (config_len=%d)", len(config_blob))

    messages = _FEW_SHOT + [{"role": "user", "content": config_blob}]

    response = _client.messages.create(
        model=_model,
        max_tokens=4096,
        system=[
            {
                "type": "text",
                "text": SYSTEM_PROMPT,
                "cache_control": {"type": "ephemeral"},
            }
        ],
        messages=messages,
    )

    raw = _strip_fences(response.content[0].text)

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        logger.error("Router config agent returned non-JSON: %s", raw[:300])
        parsed = {
            "findings": [],
            "risk_score": 0,
            "summary": "Agent output could not be parsed. Raw response logged server-side.",
            "immediate_actions": [],
        }

    usage = getattr(response, "usage", None)
    cache_read = getattr(usage, "cache_read_input_tokens", 0)
    logger.info(
        "Router analysis done: findings=%d risk_score=%d cache_read=%d",
        len(parsed.get("findings", [])),
        parsed.get("risk_score", 0),
        cache_read,
    )

    return json.dumps(parsed)
