"""Backward-compatible entrypoint.

The orchestrator graph now lives in `supervisor.py`. This module re-exports
`run_hunt` so existing imports (`from orchestrator.graph import run_hunt`) and
the FastAPI layer keep working.
"""

from .supervisor import build_graph, run_hunt

__all__ = ["run_hunt", "build_graph"]
