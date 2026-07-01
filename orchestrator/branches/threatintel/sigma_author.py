"""LLM Sigma-rule authoring.

Given resolved ATT&CK techniques (from `attack_mapper`) plus optional kill-chain
narrative, a frontier model drafts one Sigma detection rule per technique. Output
is structured (`SigmaDraft`) so we get valid, parseable fields; the raw YAML is
assembled deterministically here to guarantee well-formed Sigma regardless of the
model's whitespace habits — important when running on a smaller local model.
"""

from __future__ import annotations

import logging

import yaml
from pydantic import BaseModel, Field

from ...llm import structured
from ...state import SigmaRule
from .attack_mapper import Technique

logger = logging.getLogger(__name__)


class SigmaDraft(BaseModel):
    """One drafted detection, as structured fields (not raw YAML)."""

    title: str
    description: str = ""
    logsource_product: str = Field(default="", description="e.g. windows, linux")
    logsource_category: str = Field(
        default="", description="e.g. process_creation, network_connection, dns_query"
    )
    logsource_service: str = Field(default="", description="e.g. sysmon, security")
    # detection is a mapping of field-modifiers to match values, e.g.
    # {"Image|endswith": "\\powershell.exe", "CommandLine|contains": ["-enc","-w hidden"]}
    detection: dict = Field(default_factory=dict)
    condition: str = "selection"
    level: str = "medium"
    falsepositives: list[str] = Field(default_factory=list)


class SigmaDraftBatch(BaseModel):
    drafts: list[SigmaDraft] = Field(default_factory=list)


SYSTEM_PROMPT = """You are a detection engineer who writes precise Sigma rules.

You receive a list of ATT&CK techniques (id, name, tactic) that form an adversary
kill chain, plus optional narrative context. For EACH technique, draft one Sigma
detection as structured fields:
- Choose the correct logsource (product/category/service) for the technique.
- Put detection logic in `detection` as a mapping of Sigma field-modifier keys to
  values, e.g. {"Image|endswith": "\\\\powershell.exe", "CommandLine|contains": ["-enc"]}.
  Use a single logical group named by `condition` (default "selection").
- Prefer robust, behavior-based logic over brittle exact strings. Avoid matching on
  attacker-chosen values (filenames, IPs) unless they are stable IOCs.
- Set `level` per severity of the behavior (informational/low/medium/high/critical).
- Add realistic `falsepositives` where relevant.

Return one draft per input technique, in the same order. Do not invent techniques."""


def _draft_to_yaml(draft: SigmaDraft, technique: Technique) -> str:
    logsource = {
        k: v
        for k, v in {
            "product": draft.logsource_product,
            "category": draft.logsource_category,
            "service": draft.logsource_service,
        }.items()
        if v
    }
    rule = {
        "title": draft.title,
        "status": "experimental",
        "description": draft.description,
        "references": [f"https://attack.mitre.org/techniques/{technique.technique_id.replace('.', '/')}/"],
        "tags": [
            f"attack.{technique.tactic.split(',')[0]}" if technique.tactic else "attack",
            f"attack.{technique.technique_id.lower()}",
        ],
        "logsource": logsource or {"product": "windows"},
        "detection": {
            draft.condition: draft.detection or {},
            "condition": draft.condition,
        },
        "falsepositives": draft.falsepositives or ["Unknown"],
        "level": draft.level or "medium",
    }
    return yaml.safe_dump(rule, sort_keys=False, default_flow_style=False, allow_unicode=True)


def author_rules(techniques: list[Technique], narrative: str = "") -> list[SigmaRule]:
    if not techniques:
        return []

    tech_lines = "\n".join(
        f"- {t.technique_id} {t.name} (tactic: {t.tactic or 'unknown'})" for t in techniques
    )
    user = f"Techniques (kill chain):\n{tech_lines}"
    if narrative.strip():
        user += f"\n\nAnalyst narrative / scheme of maneuver:\n{narrative.strip()}"

    try:
        model = structured("sigma", SigmaDraftBatch)
        batch: SigmaDraftBatch = model.invoke(
            [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": user}]
        )
    except Exception:  # noqa: BLE001 — a model outage shouldn't sink the hunt
        logger.exception("Sigma author LLM failed; no rules drafted")
        return []

    rules: list[SigmaRule] = []
    # Pair drafts with techniques positionally; guard against count mismatch.
    for i, technique in enumerate(techniques):
        if i >= len(batch.drafts):
            break
        draft = batch.drafts[i]
        rules.append(
            SigmaRule(
                technique=technique.technique_id,
                title=draft.title,
                yaml=_draft_to_yaml(draft, technique),
            )
        )
    logger.info("Sigma author: drafted %d rules", len(rules))
    return rules
