"""Obsidian network-map writer.

Emits one markdown note per host into the vault. Each note carries YAML
frontmatter (OS, ports, role) and `[[wikilinks]]` to peer hosts, so Obsidian's
native Graph View renders the network topology and the frontmatter stays
queryable (Dataview, search). Also writes an index note linking every host.

Deterministic — no LLM. Edges come from observed traffic peers (ES top-talkers)
when available, so the graph reflects real communication, not just scan order.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from ...config import settings
from ...state import Host, TrafficStat

logger = logging.getLogger(__name__)


def _slug(ip: str) -> str:
    """Note filename stem for a host. IPs are filesystem-safe already."""
    return re.sub(r"[^\w.\-]", "_", ip)


def _yaml_list(items: list[str]) -> str:
    if not items:
        return "[]"
    return "\n" + "\n".join(f"  - {i}" for i in items)


def _host_note(host: Host, peers: list[str]) -> str:
    ports = [f"{s.port}/{s.protocol}" for s in host.services]
    svc_names = [s.name for s in host.services if s.name]
    front = [
        "---",
        f"ip: {host.ip}",
        f"hostname: {host.hostname}",
        f'os: "{host.os}"',
        f"status: {host.status}",
        f"role: {host.role}",
        f"ports:{_yaml_list(ports)}",
        f"services:{_yaml_list(svc_names)}",
        "tags:",
        "  - host",
        "---",
        "",
        f"# {host.hostname or host.ip}",
        "",
        f"- **IP:** {host.ip}",
        f"- **OS:** {host.os or 'unknown'}"
        + (f" (accuracy {host.os_accuracy}%)" if host.os_accuracy else ""),
        f"- **Role:** {host.role or 'unclassified'}",
        "",
        "## Open services",
    ]
    if host.services:
        for s in host.services:
            desc = " ".join(x for x in [s.product, s.version] if x)
            front.append(f"- `{s.port}/{s.protocol}` {s.name} {('— ' + desc) if desc else ''}".rstrip())
    else:
        front.append("- _none observed_")

    front += ["", "## Communicates with"]
    if peers:
        # Wikilinks drive the Obsidian graph edges.
        front += [f"- [[{_slug(p)}]]" for p in peers]
    else:
        front.append("- _no peer traffic observed_")
    front.append("")
    return "\n".join(front)


def write_network_map(
    hosts: list[Host],
    traffic: list[TrafficStat] | None = None,
    vault_path: str | None = None,
) -> str:
    """Write host notes + an index note. Returns the network-map directory path."""
    base = Path(vault_path or settings.vault_path) / "network"
    base.mkdir(parents=True, exist_ok=True)

    # Map ip -> observed peers from traffic (edges). Only link peers we also
    # have a note for OR that appear as a talker, to keep the graph meaningful.
    peer_map: dict[str, list[str]] = {}
    known = {h.ip for h in hosts}
    for t in traffic or []:
        peer_map.setdefault(t.ip, [])
        for p in t.peers:
            peer_map[t.ip].append(p)
            known.add(p)  # peers become graph nodes even if unscanned

    # Ensure every graph node (scanned host, talker, or peer) has a note, so the
    # Obsidian graph is fully resolved and external infra (e.g. C2) is taggable.
    hosts_by_ip = {h.ip: h for h in hosts}
    for node in known:
        hosts_by_ip.setdefault(node, Host(ip=node, status="up", role="observed (traffic only)"))

    for ip, host in hosts_by_ip.items():
        note = _host_note(host, peer_map.get(ip, []))
        (base / f"{_slug(ip)}.md").write_text(note, encoding="utf-8")

    # Index note.
    index = ["---", "tags:", "  - network-map", "---", "", "# Network Map", "",
             f"{len(hosts_by_ip)} hosts.", ""]
    for ip in sorted(hosts_by_ip):
        h = hosts_by_ip[ip]
        label = h.hostname or ip
        index.append(f"- [[{_slug(ip)}|{label}]] — {h.os or 'unknown OS'}")
    (base / "Network Map.md").write_text("\n".join(index) + "\n", encoding="utf-8")

    logger.info("Wrote network map: %d notes -> %s", len(hosts_by_ip), base)
    return str(base)
