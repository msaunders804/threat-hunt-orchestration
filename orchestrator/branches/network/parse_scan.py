"""Deterministic parsers for nmap and fping output → normalized Host inventory.

No LLM involved: scan output is structured, so parse it exactly rather than
paying latency/nondeterminism to a model. Supports:

  * nmap XML  (`nmap -oX`) — richest: hosts, ports, services, OS guesses
  * nmap greppable/normal text — best-effort fallback
  * fping      — liveness only (`fping -a`, or "host is alive" lines)

`parse_scan(text)` autodetects the format and returns `list[Host]`.
"""

from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET

from ...state import Host, Service

logger = logging.getLogger(__name__)

_IPV4 = r"(?:\d{1,3}\.){3}\d{1,3}"


def parse_nmap_xml(text: str) -> list[Host]:
    hosts: list[Host] = []
    # Slice out just the <nmaprun>…</nmaprun> element: analysts often paste scan
    # XML alongside narrative text, which would otherwise break XML parsing.
    start = text.find("<nmaprun")
    end = text.rfind("</nmaprun>")
    if start != -1 and end != -1:
        text = text[start : end + len("</nmaprun>")]
    root = ET.fromstring(text)
    for host_el in root.findall("host"):
        status = host_el.find("status")
        state = status.get("state", "up") if status is not None else "up"

        ip = ""
        for addr in host_el.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                ip = addr.get("addr", "")
                break
        if not ip:
            continue

        hostname = ""
        hostnames = host_el.find("hostnames")
        if hostnames is not None:
            hn = hostnames.find("hostname")
            if hn is not None:
                hostname = hn.get("name", "")

        os_name, os_accuracy = "", None
        os_el = host_el.find("os")
        if os_el is not None:
            match = os_el.find("osmatch")
            if match is not None:
                os_name = match.get("name", "")
                acc = match.get("accuracy")
                os_accuracy = int(acc) if acc and acc.isdigit() else None

        services: list[Service] = []
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                st = port_el.find("state")
                if st is not None and st.get("state") != "open":
                    continue
                svc = port_el.find("service")
                services.append(
                    Service(
                        port=int(port_el.get("portid", "0")),
                        protocol=port_el.get("protocol", "tcp"),
                        name=svc.get("name", "") if svc is not None else "",
                        product=svc.get("product", "") if svc is not None else "",
                        version=svc.get("version", "") if svc is not None else "",
                    )
                )

        hosts.append(
            Host(
                ip=ip,
                hostname=hostname,
                os=os_name,
                os_accuracy=os_accuracy,
                status=state,
                services=services,
            )
        )
    logger.info("Parsed nmap XML: %d hosts", len(hosts))
    return hosts


def parse_fping(text: str) -> list[Host]:
    """fping liveness. Handles `-a` (bare IPs) and 'x.x.x.x is alive' formats."""
    alive: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        m = re.match(rf"^({_IPV4})(?:\s+is alive)?$", line)
        if m:
            alive.add(m.group(1))
    hosts = [Host(ip=ip, status="up") for ip in sorted(alive)]
    logger.info("Parsed fping: %d live hosts", len(hosts))
    return hosts


def parse_nmap_text(text: str) -> list[Host]:
    """Best-effort parse of `nmap` normal output when XML isn't available."""
    hosts: list[Host] = []
    blocks = re.split(r"(?=Nmap scan report for )", text)
    for block in blocks:
        m = re.search(rf"Nmap scan report for (?:(\S+) )?\(?({_IPV4})\)?", block)
        if not m:
            continue
        hostname = m.group(1) or ""
        ip = m.group(2)
        services: list[Service] = []
        for pm in re.finditer(
            r"^(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?$", block, re.MULTILINE
        ):
            services.append(
                Service(
                    port=int(pm.group(1)),
                    protocol=pm.group(2),
                    name=pm.group(3),
                    product=(pm.group(4) or "").strip(),
                )
            )
        os_name = ""
        om = re.search(r"OS details: (.+)", block)
        if om:
            os_name = om.group(1).strip()
        hosts.append(Host(ip=ip, hostname=hostname, os=os_name, services=services))
    logger.info("Parsed nmap text: %d hosts", len(hosts))
    return hosts


def parse_scan(text: str) -> list[Host]:
    """Autodetect scan format and return a normalized host inventory."""
    stripped = text.lstrip()
    if stripped.startswith("<?xml") or "<nmaprun" in text:
        try:
            return parse_nmap_xml(text)
        except ET.ParseError as exc:
            logger.warning("nmap XML parse failed (%s); trying text", exc)
    if "Nmap scan report for" in text:
        return parse_nmap_text(text)
    if re.search(rf"^{_IPV4}(?:\s+is alive)?$", text.strip(), re.MULTILINE):
        return parse_fping(text)
    logger.warning("Unrecognized scan format; no hosts parsed")
    return []
