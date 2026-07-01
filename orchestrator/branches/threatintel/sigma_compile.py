"""Write Sigma rules to disk and compile them to Elasticsearch queries.

Deterministic post-processing of the authored rules:
  * validate + lint each rule by parsing it with pySigma,
  * compile to a Lucene query (the ES backend) for immediate hunting,
  * persist the YAML into the vault's detections folder.

pySigma is imported lazily and failures degrade gracefully: a rule that won't
compile still gets written (marked), so a bad draft never sinks the whole run.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from ...config import settings
from ...state import SigmaRule

logger = logging.getLogger(__name__)


def _slug(title: str) -> str:
    s = re.sub(r"[^\w\s-]", "", title).strip().lower()
    return re.sub(r"[\s_-]+", "_", s) or "rule"


def _compile_one(rule_yaml: str) -> tuple[str, str]:
    """Return (lucene_query, error). Empty error means success."""
    try:
        from sigma.backends.elasticsearch import LuceneBackend
        from sigma.collection import SigmaCollection

        collection = SigmaCollection.from_yaml(rule_yaml)
        queries = LuceneBackend().convert(collection)
        return (queries[0] if queries else ""), ""
    except ImportError:
        return "", "pySigma not installed"
    except Exception as exc:  # noqa: BLE001 — surface any pySigma parse/convert error
        return "", f"{type(exc).__name__}: {exc}"


def compile_and_write(rules: list[SigmaRule], out_dir: str | None = None) -> list[SigmaRule]:
    base = Path(out_dir or settings.sigma_output_path)
    base.mkdir(parents=True, exist_ok=True)

    compiled: list[SigmaRule] = []
    for rule in rules:
        query, error = _compile_one(rule.yaml)
        fname = f"{rule.technique.lower().replace('.', '_')}_{_slug(rule.title)}.yml"
        path = base / fname
        path.write_text(rule.yaml, encoding="utf-8")
        if error:
            logger.warning("Sigma compile failed for %s: %s", rule.technique, error)
        compiled.append(
            rule.model_copy(update={"path": str(path), "backend_query": query})
        )
    logger.info(
        "Sigma: wrote %d rules to %s (%d compiled to ES query)",
        len(compiled),
        base,
        sum(1 for r in compiled if r.backend_query),
    )
    return compiled
