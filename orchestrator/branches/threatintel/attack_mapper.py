"""MITRE ATT&CK technique validation and enrichment.

Takes an adversary "scheme of maneuver" — a list of ATT&CK technique IDs
(optionally with free-text kill-chain notes) — and resolves each T-code to its
name and tactic. This gives the Sigma author accurate, grounded context per
technique instead of relying on the model to remember every ID.

Data source, in priority order (both offline):
  1. data/attack/enterprise-attack.json  — full MITRE STIX bundle if present
  2. data/attack/techniques_min.json      — shipped curated subset (fallback)
"""

from __future__ import annotations

import json
import logging
import re
from functools import lru_cache
from pathlib import Path

from pydantic import BaseModel

logger = logging.getLogger(__name__)

_DATA_DIR = Path(__file__).parent.parent.parent.parent / "data" / "attack"
_TCODE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


class Technique(BaseModel):
    technique_id: str
    name: str = ""
    tactic: str = ""
    known: bool = False


@lru_cache
def _load_catalog() -> dict[str, dict]:
    full = _DATA_DIR / "enterprise-attack.json"
    if full.exists():
        return _parse_stix(full)
    minimal = _DATA_DIR / "techniques_min.json"
    if minimal.exists():
        with open(minimal, encoding="utf-8") as f:
            logger.info("ATT&CK: using curated minimal catalog")
            return json.load(f)
    logger.warning("ATT&CK: no catalog found in %s", _DATA_DIR)
    return {}


def _parse_stix(path: Path) -> dict[str, dict]:
    """Flatten a MITRE STIX bundle into {Txxxx: {name, tactic}}."""
    with open(path, encoding="utf-8") as f:
        bundle = json.load(f)
    catalog: dict[str, dict] = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        ext = next(
            (r for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"),
            None,
        )
        if not ext:
            continue
        tid = ext.get("external_id", "")
        tactics = ",".join(
            p.get("phase_name", "") for p in obj.get("kill_chain_phases", [])
        )
        catalog[tid] = {"name": obj.get("name", ""), "tactic": tactics}
    logger.info("ATT&CK: parsed %d techniques from STIX", len(catalog))
    return catalog


def extract_tcodes(text: str) -> list[str]:
    """Pull T-codes from free-form scheme-of-maneuver text, preserving order."""
    seen: list[str] = []
    for m in _TCODE_RE.findall(text or ""):
        if m not in seen:
            seen.append(m)
    return seen


def resolve(tcodes: list[str]) -> list[Technique]:
    catalog = _load_catalog()
    out: list[Technique] = []
    for tid in tcodes:
        entry = catalog.get(tid)
        # Fall back to the parent technique for an unlisted sub-technique.
        if entry is None and "." in tid:
            entry = catalog.get(tid.split(".")[0])
        if entry:
            out.append(
                Technique(technique_id=tid, name=entry["name"], tactic=entry["tactic"], known=True)
            )
        else:
            logger.warning("ATT&CK: unknown technique %s", tid)
            out.append(Technique(technique_id=tid, known=False))
    return out
