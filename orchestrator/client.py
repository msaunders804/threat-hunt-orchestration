import os

import anthropic

DIRECT_MODEL = "claude-sonnet-4-6"
# GovCloud Bedrock model ID — set BEDROCK_MODEL_ID in .env to override
BEDROCK_MODEL = os.environ.get(
    "BEDROCK_MODEL_ID",
    "anthropic.claude-sonnet-4-6-20251114-v1:0",
)


def get_client() -> anthropic.Anthropic:
    if os.environ.get("INFERENCE_PROVIDER") == "bedrock":
        from anthropic import AnthropicBedrock

        return AnthropicBedrock(
            aws_region=os.environ.get("AWS_REGION", "us-gov-west-1"),
        )
    return anthropic.Anthropic()


def get_model() -> str:
    if os.environ.get("INFERENCE_PROVIDER") == "bedrock":
        return BEDROCK_MODEL
    return DIRECT_MODEL


# Module-level singletons — created once at import time from env
_client = get_client()
_model = get_model()
