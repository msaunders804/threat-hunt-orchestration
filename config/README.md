# Production: provider selection (Anthropic / Bedrock / Ollama)

All model access goes through a single factory, `orchestrator/llm.py`, driven by
`orchestrator/config.py` (env vars). Switching providers is an `.env` change —
no code edits.

## How it works

`get_chat_model(role)` reads `INFERENCE_PROVIDER` and returns a LangChain chat
model. Bedrock and Ollama back ends are imported lazily, so their dependencies
are only required when that provider is selected.

```python
# orchestrator/llm.py (abridged)
if provider == "anthropic":
    return ChatAnthropic(model=model_id, ...)
if provider == "bedrock":
    return ChatBedrockConverse(model=settings.bedrock_model_id, region_name=settings.aws_region, ...)
if provider == "ollama":
    return ChatOllama(model=model_id, base_url=settings.ollama_base_url)
```

Prompt caching (`cache_control: ephemeral`) is applied only on cache-capable
providers (Anthropic, Bedrock) via `orchestrator/llm_util.cached_system`; on
Ollama it degrades to a plain system prompt automatically.

## AWS GovCloud Bedrock

1. `pip install -r requirements.txt` (includes `langchain-aws`).
2. In `.env`:

```dotenv
INFERENCE_PROVIDER=bedrock
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
AWS_REGION=us-gov-west-1
BEDROCK_MODEL_ID=anthropic.claude-sonnet-4-6-20251114-v1:0
```

3. Verify the model ID (GovCloud availability can lag commercial):

```bash
aws bedrock list-foundation-models --region us-gov-west-1 \
  --query 'modelSummaries[?contains(modelId, `claude`)].modelId' --output table
```

4. IAM: the execution role needs `bedrock:InvokeModel` (+ `WithResponseStream`)
   on `arn:aws-us-gov:bedrock:us-gov-west-1::foundation-model/anthropic.claude-*`.

5. Restart. The model factory caches per role at first use.

## Fully local (Ollama)

```dotenv
INFERENCE_PROVIDER=ollama
DIRECT_MODEL=llama3.1:8b
OLLAMA_BASE_URL=http://localhost:11434
```

Structured-output agents (vuln triage, Sigma authoring, routing) use
`.with_structured_output(...)`, which keeps JSON reliable even on smaller local
models. Use per-role overrides to run only some roles locally — see
`.env.example`.

## Air-gapped checklist

- `INFERENCE_PROVIDER=bedrock` or `ollama` (no direct Anthropic egress)
- `ES_MODE=live` pointed at the internal cluster (or `mock` for demos)
- `EXTERNAL_TI_ENABLED=false` (no VirusTotal/Shodan/OTX calls)
- ATT&CK: ship `data/attack/enterprise-attack.json` offline (optional)
