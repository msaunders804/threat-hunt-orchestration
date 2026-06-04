import json
import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

_CVE_PATH = Path(__file__).parent.parent.parent.parent / "data" / "cve_mock.json"
_EOS_PATH = Path(__file__).parent.parent.parent.parent / "data" / "ios_eos.json"

_cve_db: dict | None = None
_eos_db: dict | None = None


def _load_cve() -> dict:
    global _cve_db
    if _cve_db is None:
        with open(_CVE_PATH, encoding="utf-8") as f:
            _cve_db = json.load(f)
    return _cve_db


def _load_eos() -> dict:
    global _eos_db
    if _eos_db is None:
        with open(_EOS_PATH, encoding="utf-8") as f:
            _eos_db = json.load(f)
    return _eos_db


def lookup_cve(cve_id: str) -> str:
    """Look up details for a specific CVE relevant to Cisco IOS or IOS XE.

    Returns CVSS score, severity, affected platforms, description, and remediation.
    Call this whenever you identify a configuration pattern known to be associated
    with a published CVE (e.g. Smart Install enabled, HTTP server enabled, SNMP v1/v2c).

    Args:
        cve_id: CVE identifier (e.g. "CVE-2018-0171")
    """
    entry = _load_cve().get(cve_id.upper().strip())
    if entry:
        result = {"cve_id": cve_id, "found": True, **entry}
    else:
        result = {"cve_id": cve_id, "found": False, "description": "CVE not in local database"}
    logger.debug("lookup_cve(%s) -> found=%s", cve_id, result["found"])
    return json.dumps(result)


def check_ios_eos(version: str) -> str:
    """Check whether a Cisco IOS or IOS XE version is end-of-support or end-of-life.

    Always call this tool when you can identify the IOS version in the config
    (e.g. from a 'version 15.2' or 'version 16.9.3' line).
    Returns status (active/end_of_support/end_of_life/unknown) and key dates.

    Args:
        version: IOS version string in any format (e.g. "15.2", "16.9.3", "Version 12.4(24)T")
    """
    match = re.search(r'(\d+\.\d+)', version)
    if not match:
        return json.dumps({"version": version, "found": False, "status": "unknown",
                           "note": "Could not parse version string"})
    major_minor = match.group(1)
    entry = _load_eos().get(major_minor)
    if entry:
        result = {"version": version, "parsed_major_minor": major_minor, "found": True, **entry}
    else:
        result = {"version": version, "parsed_major_minor": major_minor, "found": False,
                  "status": "unknown", "note": "Version not in local EOS database"}
    logger.debug("check_ios_eos(%s) -> status=%s", version, result.get("status"))
    return json.dumps(result)


_HARDENING_GUIDANCE: dict[str, str] = {
    "snmp": (
        "Disable SNMPv1/v2c; migrate to SNMPv3 with authPriv (SHA + AES-128). "
        "Restrict with ACL: snmp-server community <string> RO <ACL>. "
        "Remove if unused: no snmp-server."
    ),
    "telnet": (
        "Disable Telnet: line vty 0 4 / transport input ssh. "
        "Enforce SSHv2: ip ssh version 2. "
        "Set idle timeout: ip ssh time-out 60 / exec-timeout 5 0."
    ),
    "acl": (
        "Apply inbound ACLs on all WAN-facing interfaces. "
        "Anti-spoofing: deny ip 10.0.0.0 0.255.255.255 any / deny ip 172.16.0.0 0.15.255.255 any / "
        "deny ip 192.168.0.0 0.0.255.255 any. End every ACL: deny ip any any log."
    ),
    "bgp": (
        "Enable MD5 authentication: neighbor <ip> password <key>. "
        "Max-prefix limits: neighbor <ip> maximum-prefix <n> 80. "
        "Filter with route-maps on inbound/outbound prefixes."
    ),
    "logging": (
        "Remote syslog: logging host <ip>. "
        "Buffered: logging buffered 64000 informational. "
        "Timestamps: service timestamps log datetime msec localtime show-timezone. "
        "Sequence numbers: service sequence-numbers."
    ),
    "passwords": (
        "Enable service password-encryption. "
        "Use type 8/9 for enable secret: enable algorithm-type scrypt secret <pw>. "
        "Remove all type 0 plaintext and type 7 passwords."
    ),
    "cdp": (
        "Disable on external interfaces: interface <x> / no cdp enable. "
        "Disable globally if no Cisco IP phones: no cdp run."
    ),
    "vty": (
        "Restrict by source IP: line vty 0 4 / access-class MGMT-ACL in. "
        "Example: ip access-list standard MGMT-ACL / permit 10.0.0.0 0.255.255.255 / deny any log."
    ),
}


def get_hardening_guidance(topic: str) -> str:
    """Retrieve specific Cisco IOS hardening commands for a security topic.

    Available topics: snmp, telnet, acl, bgp, logging, passwords, cdp, vty.
    Call this to get exact IOS commands to include in remediation recommendations.

    Args:
        topic: Security topic to get guidance for (e.g. "snmp", "telnet", "passwords")
    """
    topic_lower = topic.lower()
    for key, guidance in _HARDENING_GUIDANCE.items():
        if key in topic_lower:
            result = {"topic": topic, "found": True, "guidance": guidance}
            logger.debug("get_hardening_guidance(%s) -> found", topic)
            return json.dumps(result)
    result = {
        "topic": topic,
        "found": False,
        "available_topics": list(_HARDENING_GUIDANCE.keys()),
        "note": "No exact match. Try one of the available_topics.",
    }
    logger.debug("get_hardening_guidance(%s) -> not found", topic)
    return json.dumps(result)
