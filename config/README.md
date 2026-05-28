# Production: Swapping to AWS GovCloud Bedrock

The orchestrator uses `orchestrator/client.py` as a single client factory. Swapping from the Anthropic direct API to Bedrock requires **only `.env` changes** — no code edits.

## How it works

`orchestrator/client.py` checks `INFERENCE_PROVIDER` at startup:

```python
def get_client():
    if os.environ.get("INFERENCE_PROVIDER") == "bedrock":
        from anthropic import AnthropicBedrock
        return AnthropicBedrock(aws_region=os.environ.get("AWS_REGION", "us-gov-west-1"))
    return anthropic.Anthropic()
```

`AnthropicBedrock` is a drop-in replacement for `anthropic.Anthropic` — the same `.messages.create()` call, the same response shape, and the same prompt-caching headers all work identically.

## Swap procedure

1. **Copy `.env.example` to `.env`** (if not already done).

2. **Comment out `ANTHROPIC_API_KEY`** — it is not used on Bedrock.

3. **Uncomment and fill in the Bedrock block:**

```dotenv
INFERENCE_PROVIDER=bedrock
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
AWS_REGION=us-gov-west-1
BEDROCK_MODEL_ID=anthropic.claude-sonnet-4-6-20251114-v1:0
```

4. **Verify the model ID** — GovCloud model availability may lag commercial regions. Check the current list:

```bash
aws bedrock list-foundation-models \
  --region us-gov-west-1 \
  --query 'modelSummaries[?contains(modelId, `claude`)].modelId' \
  --output table
```

   Replace `BEDROCK_MODEL_ID` with the exact ID returned (date suffixes are required by Bedrock).

5. **IAM permissions** — the execution role needs:

```json
{
  "Effect": "Allow",
  "Action": ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"],
  "Resource": "arn:aws-us-gov:bedrock:us-gov-west-1::foundation-model/anthropic.claude-*"
}
```

6. **Restart the server.** The client singleton is created once at import time.

## Prompt caching on Bedrock

Prompt caching (`cache_control: {"type": "ephemeral"}`) is supported on Bedrock for Claude models that support it. The same blocks in `intent_classifier.py`, `router_config.py`, and `synthesis.py` will be transparently cached. Verify with `usage.cache_read_input_tokens > 0` in logs after the second request.

## Reverting to direct API

Set `INFERENCE_PROVIDER=anthropic` (or remove the variable) and restore `ANTHROPIC_API_KEY`. Restart.
