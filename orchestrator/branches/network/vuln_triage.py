"""LLM vulnerability / OS-exposure triage.

Given the normalized host inventory (OS + service products/versions from the
scan), a frontier model flags hosts likely to be vulnerable — outdated OSes,
end-of-life software, risky exposed services, dangerous version strings — and
maps them to known CVE classes where confident.

Uses structured output (`with_structured_output`) so the result is a validated
`VulnReport`, which keeps this reliable even on a smaller local model.
"""

from __future__ import annotations

import logging

from pydantic import BaseModel, Field

from ...llm import structured
from ...state import Host, VulnFinding

logger = logging.getLogger(__name__)


class VulnReport(BaseModel):
    findings: list[VulnFinding] = Field(default_factory=list)


SYSTEM_PROMPT = """You are a vulnerability-assessment specialist supporting a threat hunt.

You receive a normalized inventory of hosts discovered by nmap: IP, OS guess, and
open services with product/version strings. Identify hosts that are LIKELY
vulnerable and explain why. Focus on:
- End-of-life / outdated operating systems (e.g. Windows 7/2003/2008, old Linux kernels)
- Outdated or known-vulnerable service versions (e.g. Apache 2.2.x, OpenSSH < 7.4,
  SMBv1, old OpenSSL, vsftpd 2.3.4, ProFTPD, outdated Exchange/IIS)
- Dangerous exposed services (Telnet, unauthenticated RDP/VNC, SMB to untrusted zones,
  database ports exposed, legacy management protocols)
- Well-known CVE classes when the version strongly implies them (name the CVE only
  when the version match is high-confidence; otherwise describe the class)

Rules:
- Only report hosts with a real, defensible concern. Do not invent versions.
- Severity: critical = remotely exploitable / EOL with public exploits; high = likely
  exploitable or major exposure; medium = weakens posture; low = hygiene; informational = note.
- `evidence` must quote the exact OS or service/version string that triggered the finding.
- If nothing is concerning, return an empty findings list."""


def _inventory_text(hosts: list[Host]) -> str:
    lines = []
    for h in hosts:
        svc = "; ".join(
            f"{s.port}/{s.protocol} {s.name} {s.product} {s.version}".strip()
            for s in h.services
        )
        lines.append(f"- {h.ip} | OS: {h.os or 'unknown'} | services: {svc or 'none'}")
    return "\n".join(lines)


def triage_hosts(hosts: list[Host]) -> list[VulnFinding]:
    if not hosts:
        return []
    inventory = _inventory_text(hosts)
    try:
        model = structured("triage", VulnReport)
        result: VulnReport = model.invoke(
            [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": f"Host inventory:\n{inventory}"},
            ]
        )
    except Exception:  # noqa: BLE001 — keep deterministic artifacts flowing if LLM is down
        logger.exception("Vuln triage LLM failed; returning no findings")
        return []
    logger.info("Vuln triage: %d findings over %d hosts", len(result.findings), len(hosts))
    return result.findings
