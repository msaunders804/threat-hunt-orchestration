"""Unified LLM provider factory.

Every agent obtains its chat model through `get_chat_model(role)` — never by
constructing a provider client directly. This is the single seam that lets the
whole orchestrator run on frontier APIs today and swap to local SLMs (Ollama)
or GovCloud Bedrock with no agent-code changes.

Design notes:
  * Returns a LangChain `BaseChatModel`, which `deepagents.create_deep_agent`
    accepts directly (in place of a "provider:model" string) and which every
    branch node can call uniformly.
  * `bedrock` and `ollama` back ends are imported lazily so their (heavy /
    optional) dependencies are only required when that provider is selected.
  * `structured(role, schema)` returns a model bound to a Pydantic schema via
    `.with_structured_output`, giving reliable JSON across providers — the main
    reliability gap when downgrading to a small local model.
"""

from __future__ import annotations

import logging
from functools import lru_cache
from typing import Any

from langchain_core.language_models.chat_models import BaseChatModel

from .config import Role, settings

logger = logging.getLogger(__name__)

# Providers that support Anthropic-style ephemeral prompt caching. Agents can
# check this before attaching cache_control blocks.
CACHE_CAPABLE = {"anthropic", "bedrock"}


def supports_prompt_caching() -> bool:
    return settings.provider in CACHE_CAPABLE


def _build_model(model_id: str, **kwargs: Any) -> BaseChatModel:
    provider = settings.provider

    if provider == "anthropic":
        from langchain_anthropic import ChatAnthropic

        return ChatAnthropic(model=model_id, max_tokens=4096, **kwargs)

    if provider == "bedrock":
        # Lazy: langchain-aws pulls boto3; only needed in the Bedrock deployment.
        from langchain_aws import ChatBedrockConverse

        return ChatBedrockConverse(
            model=settings.bedrock_model_id,
            region_name=settings.aws_region,
            max_tokens=4096,
            **kwargs,
        )

    if provider == "ollama":
        # Lazy: langchain-ollama only needed for fully-local operation.
        from langchain_ollama import ChatOllama

        return ChatOllama(
            model=model_id,
            base_url=settings.ollama_base_url,
            **kwargs,
        )

    raise ValueError(f"Unknown INFERENCE_PROVIDER: {provider!r}")


@lru_cache(maxsize=None)
def get_chat_model(role: Role = "synthesis") -> BaseChatModel:
    """Return a chat model for a logical role (router/parse/triage/sigma/synthesis).

    The concrete model id is resolved per-provider from `settings`, honoring any
    per-role override (e.g. ROUTER_MODEL=llama3.1:8b to run only routing local).
    """
    model_id = settings.model_for(role)
    logger.info(
        "LLM factory: role=%s provider=%s model=%s",
        role,
        settings.provider,
        model_id if settings.provider != "bedrock" else settings.bedrock_model_id,
    )
    return _build_model(model_id)


def structured(role: Role, schema: Any) -> Any:
    """Return a model bound to a structured-output `schema` (a Pydantic model).

    Use for any agent that must emit JSON — this is what keeps small local
    models usable, since it constrains/parses their output rather than trusting
    free-form JSON in the response text.
    """
    return get_chat_model(role).with_structured_output(schema)
