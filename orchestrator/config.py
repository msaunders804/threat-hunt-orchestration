"""Central configuration for the threat hunt orchestrator.

All runtime behavior is driven by environment variables (loaded from `.env` by
`main.py` before this module is imported). The goal is a single, well-documented
seam so the same code runs against:

  * frontier models via the Anthropic API (dev),
  * AWS GovCloud Bedrock (air-gapped prod),
  * local SLMs via Ollama (fully offline),

and against either a live Elasticsearch cluster or local mock fixtures.

Import the singleton `settings` object; never read `os.environ` directly in
agent code.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

Provider = Literal["anthropic", "bedrock", "ollama"]

# Logical model roles. Each maps to a concrete model id per provider (see
# `llm.py`). Splitting roles lets cheap/local models handle routing and parsing
# while frontier models handle the reasoning-heavy work (vuln triage, Sigma
# authoring, synthesis).
Role = Literal["router", "parse", "triage", "sigma", "synthesis"]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    # ── Inference provider ───────────────────────────────────────────────
    # `INFERENCE_PROVIDER` kept as the env name for backward-compat with the
    # existing Bedrock swap docs; `anthropic` is the default.
    provider: Provider = Field(default="anthropic", alias="INFERENCE_PROVIDER")

    # Default/frontier model id, interpreted per-provider (see llm.py).
    # For anthropic this is a model like "claude-sonnet-4-6"; for ollama a tag
    # like "llama3.1:8b"; for bedrock a Bedrock model id.
    default_model: str = Field(default="claude-sonnet-4-6", alias="DIRECT_MODEL")

    # Optional per-role overrides. Empty string means "use default_model".
    # e.g. ROUTER_MODEL=llama3.1:8b to run only routing on a local SLM.
    router_model: str = Field(default="", alias="ROUTER_MODEL")
    parse_model: str = Field(default="", alias="PARSE_MODEL")
    triage_model: str = Field(default="", alias="TRIAGE_MODEL")
    sigma_model: str = Field(default="", alias="SIGMA_MODEL")
    synthesis_model: str = Field(default="", alias="SYNTHESIS_MODEL")

    # ── Bedrock ──────────────────────────────────────────────────────────
    aws_region: str = Field(default="us-gov-west-1", alias="AWS_REGION")
    bedrock_model_id: str = Field(
        default="anthropic.claude-sonnet-4-6-20251114-v1:0",
        alias="BEDROCK_MODEL_ID",
    )

    # ── Ollama ───────────────────────────────────────────────────────────
    ollama_base_url: str = Field(
        default="http://localhost:11434", alias="OLLAMA_BASE_URL"
    )

    # ── Elasticsearch ────────────────────────────────────────────────────
    es_mode: Literal["mock", "live"] = Field(default="mock", alias="ES_MODE")
    es_url: str = Field(default="http://localhost:9200", alias="ES_URL")
    # Auth: prefer an API key; basic auth (user/pass) is offered for lab convenience.
    es_api_key: str = Field(default="", alias="ES_API_KEY")
    es_username: str = Field(default="", alias="ES_USERNAME")
    es_password: str = Field(default="", alias="ES_PASSWORD")
    # Index patterns (ECS/Beats/Zeek defaults). Comma-separated allowed.
    es_flow_index: str = Field(default="packetbeat-*,zeek-conn-*", alias="ES_FLOW_INDEX")
    es_event_index: str = Field(default="logs-*,winlogbeat-*", alias="ES_EVENT_INDEX")

    # ── Threat intel connectivity ────────────────────────────────────────
    # Off by default so the air-gapped deployment never attempts egress.
    external_ti_enabled: bool = Field(default=False, alias="EXTERNAL_TI_ENABLED")
    virustotal_api_key: str = Field(default="", alias="VIRUSTOTAL_API_KEY")
    shodan_api_key: str = Field(default="", alias="SHODAN_API_KEY")
    otx_api_key: str = Field(default="", alias="OTX_API_KEY")

    # ── Output ───────────────────────────────────────────────────────────
    # Where the network-map Obsidian notes and Sigma rules are written.
    vault_path: str = Field(default="vault", alias="VAULT_PATH")
    sigma_output_path: str = Field(default="vault/detections", alias="SIGMA_OUTPUT_PATH")

    def model_for(self, role: Role) -> str:
        """Resolve a logical role to a concrete model id, honoring overrides."""
        override = {
            "router": self.router_model,
            "parse": self.parse_model,
            "triage": self.triage_model,
            "sigma": self.sigma_model,
            "synthesis": self.synthesis_model,
        }.get(role, "")
        return override or self.default_model


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
