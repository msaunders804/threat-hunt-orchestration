"""Final report synthesis.

Takes the correlated artifacts from all branches and produces the markdown report
returned to the caller (rendered in the Obsidian chat). Uses the `synthesis`
model role. A deterministic fallback renders a structured report if the LLM call
fails, so the hunt always returns something useful.
"""

from __future__ import annotations

import json
import logging

from .llm import get_chat_model
from .llm_util import cached_system, message_text
from .state import Artifacts, HuntState

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are the lead analyst writing the final report for a threat hunt.
Your output renders as markdown in an Obsidian chat window.

You receive a JSON evidence bundle produced by specialist agents (network map,
top-talkers, vulnerabilities, IOC reputation + environment hits, Sigma rules,
and cross-branch hypotheses). Write a concise, scannable report:

1. **Executive Summary** (2-3 sentences) — the "so what".
2. **Priority Leads** — the correlation hypotheses, highest confidence first, each
   with its supporting signals.
3. **Findings** — grouped: Network (map location, notable hosts/OSes, vulns),
   Threat Intel (malicious IOCs and which internal hosts touched them), Detections
   (Sigma rules authored, by technique).
4. **Recommended Actions** — specific, ordered by urgency.

Rules:
- Max 500 words. Use headers, bold, bullets. Severity emoji: 🔴 critical 🟠 high
  🟡 medium 🔵 low ⚪ informational.
- Never dump raw JSON. Reference the network map path and Sigma file paths if present.
- If a section has no data, omit it rather than writing "none"."""


def _evidence_bundle(art: Artifacts) -> dict:
    return {
        "network_map_path": art.network_map_path,
        "hosts": [h.model_dump() for h in art.hosts],
        "top_talkers": [t.model_dump() for t in art.traffic],
        "vulnerabilities": [v.model_dump() for v in art.vulns],
        "iocs": [i.model_dump() for i in art.iocs],
        "ioc_environment_hits": art.evidence.get("ioc_es_hits", []),
        "sigma_rules": [
            {"technique": r.technique, "title": r.title, "path": r.path, "query": r.backend_query}
            for r in art.sigma_rules
        ],
        "hypotheses": [h.model_dump() for h in art.hypotheses],
    }


def _fallback_report(art: Artifacts) -> str:
    lines = ["# Threat Hunt Report", ""]
    if art.hypotheses:
        lines.append("## Priority Leads")
        for h in art.hypotheses:
            lines.append(f"- **[{h.confidence}]** {h.statement}")
            for s in h.supporting:
                lines.append(f"  - {s}")
        lines.append("")
    if art.network_map_path:
        lines.append(f"## Network\n- Map written to `{art.network_map_path}` ({len(art.hosts)} hosts)")
    if art.traffic:
        lines.append("- Top talkers: " + ", ".join(f"{t.ip}" for t in art.traffic[:5]))
    if art.vulns:
        lines.append("\n## Vulnerabilities")
        for v in art.vulns:
            lines.append(f"- **{v.severity}** {v.ip}: {v.title}")
    mal = [i for i in art.iocs if i.reputation in ("malicious", "suspicious")]
    if mal:
        lines.append("\n## Threat Intel")
        for i in mal:
            lines.append(f"- {i.ioc} ({i.ioc_type}) — {i.reputation} {i.category}")
    if art.sigma_rules:
        lines.append("\n## Detections (Sigma)")
        for r in art.sigma_rules:
            lines.append(f"- {r.technique}: {r.title} → `{r.path}`")
    return "\n".join(lines) + "\n"


def synthesize(art: Artifacts) -> str:
    bundle = _evidence_bundle(art)
    try:
        response = get_chat_model("synthesis").invoke(
            [
                cached_system(SYSTEM_PROMPT),
                {"role": "user", "content": json.dumps(bundle, indent=None)},
            ]
        )
        report = message_text(response).strip()
        if report:
            return report
    except Exception:  # noqa: BLE001 — never let synthesis sink the hunt
        logger.exception("Synthesis LLM failed; using deterministic fallback")
    return _fallback_report(art)


def synthesize_node(state: HuntState) -> dict:
    art = state.get("artifacts") or Artifacts()
    return {"report": synthesize(art)}
