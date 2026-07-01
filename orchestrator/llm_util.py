"""Small helpers shared by LLM-backed agents.

Keeps provider-specific quirks (prompt caching, response-text extraction, JSON
fence stripping) in one place so individual agents stay readable.
"""

from __future__ import annotations

import re
from typing import Any

from langchain_core.messages import AIMessage, SystemMessage

from .llm import supports_prompt_caching


def strip_fences(text: str) -> str:
    """Remove ```json ... ``` code fences some models wrap JSON in."""
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*\n?", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\n?```\s*$", "", text)
    return text.strip()


def cached_system(prompt: str) -> SystemMessage:
    """System message with Anthropic ephemeral cache_control when supported.

    On providers without prompt caching (e.g. Ollama) this degrades to a plain
    string system message — same prompt, no cache directive.
    """
    if supports_prompt_caching():
        return SystemMessage(
            content=[
                {
                    "type": "text",
                    "text": prompt,
                    "cache_control": {"type": "ephemeral"},
                }
            ]
        )
    return SystemMessage(content=prompt)


def message_text(msg: AIMessage) -> str:
    """Extract plain text from an AIMessage whose content may be a block list."""
    content: Any = msg.content
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict) and block.get("type") == "text":
                parts.append(block.get("text", ""))
        return "".join(parts)
    return str(content)


def cache_read_tokens(msg: AIMessage) -> int:
    """Best-effort cache-read token count for logging (Anthropic/Bedrock)."""
    meta = getattr(msg, "response_metadata", {}) or {}
    usage = meta.get("usage", {}) if isinstance(meta, dict) else {}
    return int(usage.get("cache_read_input_tokens", 0) or 0)
