# Threat Hunt Orchestrator

A self-hosted FastAPI + LangGraph service that routes natural language threat hunting questions to specialized AI agents and returns structured markdown findings.

Designed as an optional backend for the [Obsidian Collab Relay](https://github.com/NormalTechGuy/Obsidian-Collab-Relay)  bot, but usable by any HTTP client.

---

## What it does

Send a plain-English question. Get back a markdown report.

```
@agent Is 198.51.100.10 malicious?
```
```
@agent Check this config for issues:
interface GigabitEthernet0/0
 ip address 203.0.113.1 255.255.255.0
line vty 0 4
 transport input telnet
 login local
```

The orchestrator classifies the intent, dispatches to the right agent, and synthesizes findings into a readable report — all in one `POST /api/query` call.

---

## Agents

| Agent | Trigger | What it does |
|---|---|---|
| **Router Config Analyzer** | Cisco IOS config pasted in message | Audits for ACL gaps, management plane exposure, routing protocol security, hardening misses, logging, and weak encryption. Returns severity-tagged findings and a risk score. |
| **IOC Enrichment** | IP addresses, domains, or file hashes listed | Looks up each indicator against a local database and returns reputation, category, and severity. |
| **Clarify** | Low-confidence or ambiguous input | Returns a short prompt asking the user to clarify their intent. |

Intent classification and final report synthesis are handled by Claude Sonnet via the Anthropic API (or AWS GovCloud Bedrock in production — see [Bedrock swap](#bedrock-swap)).

---

## Architecture

```
POST /api/query
      │
      ▼
 classify_intent          ← Claude Sonnet (cached system prompt)
      │
      ├─ router_config ──► analyze_router_config   ← Claude Sonnet (cached system prompt + few-shot)
      │
      ├─ ioc_enrichment ─► enrich_iocs             ← static JSON lookup, no API call
      │
      └─ clarify ────────► return clarification prompt
                                    │
                                    ▼
                           synthesize_findings      ← Claude Sonnet (cached system prompt)
                                    │
                                    ▼
                            {"summary": "..."}
```

Prompt caching is enabled on all three Claude calls. After the first warm request, system prompts are read from Anthropic's cache, reducing latency and token cost on repeated queries of the same type.

---

## Quickstart

**Requirements:** Python 3.11+, an Anthropic API key.

```bash
git clone https://github.com/<you>/threat-hunt-orchestrator.git
cd threat-hunt-orchestrator

python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install -r requirements.txt

cp .env.example .env
# edit .env — add your ANTHROPIC_API_KEY

python main.py
```

Verify:
```bash
curl http://localhost:8000/health
# {"status": "orchestrator alive"}
```

Test a query:
```bash
curl -X POST http://localhost:8000/api/query \
  -H "Content-Type: application/json" \
  -d '{"question": "Is 185.220.101.1 a known bad IP?"}'
```

---

## API

### `GET /health`
Returns `{"status": "orchestrator alive"}`. Use for container health checks.

### `POST /api/query`

**Request:**
```json
{ "question": "your natural language question or pasted config" }
```

**Response (success):**
```json
{ "summary": "markdown-formatted findings" }
```

**Response (error):**
```json
{ "error": "description" }
```

The `summary` field is rendered as markdown. When connected to Obsidian via the Jester bot, findings appear as formatted reports directly in the chat view.

---

## Connecting to Obsidian Collab Relay

The [Jester bot](https://github.com/NormalTechGuy/Obsidian-Collab-Relay) watches for `@agent` mentions in Obsidian chat and forwards the stripped message to this service.

In the bot's `.env`:
```dotenv
PWHL_API_URL=http://<this-machine-ip>:8000
```

Restart the bot container. No plugin changes required.

---

## Project structure

```
main.py                        FastAPI entrypoint
orchestrator/
  client.py                    Anthropic / Bedrock client factory
  graph.py                     LangGraph state machine
  agents/
    intent_classifier.py       Claude: classify intent, extract entities
    router_config.py           Claude: Cisco IOS security audit
    ioc_enrichment.py          Local lookup against data/ioc_mock.json
    synthesis.py               Claude: format findings as markdown
data/
  ioc_mock.json                Mock IOC database (IPs, domains, hashes)
config/
  README.md                    Bedrock swap procedure
.env.example                   Environment variable reference
requirements.txt
```

---

## Bedrock swap

The service runs against the Anthropic direct API by default. To switch to AWS GovCloud Bedrock in production, set two env vars — no code changes required:

```dotenv
INFERENCE_PROVIDER=bedrock
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
AWS_REGION=us-gov-west-1
BEDROCK_MODEL_ID=anthropic.claude-sonnet-4-6-20251114-v1:0
```

See [`config/README.md`](config/README.md) for IAM policy requirements and model ID verification steps.

---

## Extending

**Add a new agent:**
1. Create `orchestrator/agents/<name>.py` with a function `def <name>(state: dict) -> dict`.
2. Add the intent label to the classifier's system prompt.
3. Register the node and edge in `orchestrator/graph.py`.

**Replace the mock IOC database:**
Swap `data/ioc_mock.json` for calls to a real threat intel API (VirusTotal, Shodan, etc.) inside `ioc_enrichment.py`. The rest of the graph is unaffected.

---

## License

MIT
