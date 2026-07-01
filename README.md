
# Threat Hunt Orchestrator

A self-hosted FastAPI + LangGraph service that orchestrates specialist AI agents
to run threat hunts. A supervisor routes each request to one or both of two
branches — **Network Analysis** and **Threat Intelligence** — correlates their
findings, and returns a structured markdown report.

Runs on frontier models via API, and is engineered to swap to **local SLMs via
Ollama** or **AWS GovCloud Bedrock** with no code changes (air-gapped ready).

---

## What it does

Send a plain-English question, pasted scan data, or an adversary kill chain. Get
back a markdown report — plus, when relevant, an Obsidian network-map vault and
Sigma detection rules written to disk.

```
@agent Is 198.51.100.10 malicious?
@agent <paste nmap XML> — map this network and flag vulnerable hosts
@agent Build detections for this kill chain: T1566.001 -> T1059.001 -> T1071.001 -> T1041
```

---

## Architecture

```
POST /api/query
      │
      ▼
  supervisor  ── route ──┬── chat ─────────► generalist agent ──► report
 (router.py)             │                   (IOC check / config audit / Q&A)
                         │
                         └── network / threatintel / both
                                    │
             ┌──────────────────────┴───────────────────────┐
             ▼                                               ▼
     Network branch                                  Threat-Intel branch
   parse_scan → traffic →                          ioc_hunt → sigma_detect
   network_map → vuln_triage                       (enrich+ES search) (T-codes→Sigma)
             └──────────────────────┬───────────────────────┘
                                    ▼
                              correlate  (top-talkers ∩ malicious-IOC ∩ vulnerable → hypotheses)
                                    ▼
                              synthesize → markdown report
```

Everything flows through a shared, typed `HuntState` (see `orchestrator/state.py`).
All model calls go through one provider factory (`orchestrator/llm.py`), so
provider selection is env-only.

---

## Agents

| Agent | Branch | What it does |
|---|---|---|
| **Supervisor / router** | — | Routes each turn (deterministic signals first, LLM only when ambiguous). |
| **Scan parser** | Network | Parses nmap XML, nmap text, and fping into a normalized host inventory. Deterministic. |
| **Network mapper** | Network | Writes one Obsidian note per host with YAML frontmatter + `[[wikilinks]]` → renders in Graph View. Deterministic. |
| **Traffic analyst** | Network | Top-talking hosts from Elasticsearch. |
| **Vuln triage** | Network | Flags likely-vulnerable hosts/OSes from the inventory (frontier model). |
| **Router-config auditor** | Network | Cisco IOS security audit (also a generalist tool). |
| **IOC hunt** | Threat-Intel | Extracts indicators, enriches reputation (local + optional external), searches ES for where they appear. |
| **ATT&CK mapper** | Threat-Intel | Validates/enriches T-codes against offline MITRE data. |
| **Sigma author + compiler** | Threat-Intel | Drafts Sigma rules per technique (frontier), compiles to ES queries via pySigma, writes YAML. |
| **Correlation** | cross-branch | Joins signals into ranked hunt hypotheses. Deterministic. |
| **Synthesis** | cross-branch | Final markdown report (frontier, deterministic fallback). |

---

## Quickstart

**Requirements:** Python 3.11+, and either an Anthropic API key, a Bedrock role, or a local Ollama.

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env             # edit — set ANTHROPIC_API_KEY (or pick another provider)

python main.py
```

Verify:
```bash
curl http://localhost:8000/health
curl -X POST http://localhost:8000/api/query \
  -H "Content-Type: application/json" \
  -d '{"question": "Is 185.220.101.1 a known bad IP?"}'
```

---

## API

### `GET /health` → `{"status": "orchestrator alive"}`

### `POST /api/query`
```json
{ "question": "your question / pasted scan / kill chain", "session_id": "optional" }
```
Returns `{ "summary": "markdown report" }`. Network maps land in `VAULT_PATH`
(default `vault/network/`), Sigma rules in `SIGMA_OUTPUT_PATH` (default
`vault/detections/`).

---

## Switching providers (no code changes)

Set `INFERENCE_PROVIDER` in `.env`:

| Provider | Key vars | Notes |
|---|---|---|
| `anthropic` (default) | `ANTHROPIC_API_KEY`, `DIRECT_MODEL` | Frontier API. |
| `bedrock` | `AWS_REGION`, `BEDROCK_MODEL_ID` | GovCloud/air-gapped. |
| `ollama` | `OLLAMA_BASE_URL`, `DIRECT_MODEL` | Fully local SLMs. |

Per-role model overrides let you mix — e.g. run routing on a local SLM while
keeping vuln triage / Sigma authoring on a frontier model:

```dotenv
ROUTER_MODEL=llama3.1:8b
```

Roles: `router`, `parse`, `triage`, `sigma`, `synthesis` (see `.env.example`).

---

## Elasticsearch

`ES_MODE=mock` (default) serves fixtures from `data/es_mock/` — no cluster
needed for dev/tests. `ES_MODE=live` targets a real cluster (`ES_URL`,
`ES_API_KEY`); index patterns and ECS field assumptions are configurable in
`orchestrator/config.py`. See `orchestrator/services/elasticsearch.py`.

## External threat intel

Off by default (`EXTERNAL_TI_ENABLED=false`) so air-gapped deployments never
attempt egress. When enabled with an API key, unknown indicators are augmented
via connectors in `orchestrator/services/threatintel/`. Local reputation
(`data/ioc_mock.json`) and ES search always work offline.

## MITRE ATT&CK data

The ATT&CK mapper uses a shipped curated subset
(`data/attack/techniques_min.json`). Drop the full STIX bundle at
`data/attack/enterprise-attack.json` (git-ignored) to cover every technique.

---

## Project structure

```
main.py                         FastAPI entrypoint
orchestrator/
  config.py                     env-driven settings (provider, ES, TI, paths)
  llm.py / llm_util.py          provider factory + LLM helpers
  state.py                      HuntState + typed artifact models
  router.py                     supervisor routing (heuristic + LLM)
  supervisor.py                 top-level StateGraph
  correlate.py                  cross-branch hypotheses
  synthesis.py                  final report
  branches/
    network/                    parse_scan, network_map, es_traffic,
                                vuln_triage, router_config, graph
    threatintel/                ioc_search, ioc_enrich, attack_mapper,
                                sigma_author, sigma_compile, graph
  services/
    elasticsearch.py            mock + live ES seam
    threatintel/external.py     external TI connectors (flag-gated)
data/
  ioc_mock.json                 offline reputation feed
  es_mock/                      mock ES fixtures
  attack/techniques_min.json    curated ATT&CK subset
```

---

## Connecting to Obsidian Collab Relay

The [Jester bot](https://github.com/NormalTechGuy/Obsidian-Collab-Relay) forwards
`@agent` mentions to this service. In the bot's `.env`:

```dotenv
PWHL_API_URL=http://<this-machine-ip>:8000
```

Point the bot's vault at `VAULT_PATH` to browse generated network maps as a graph.

---

## License

MIT
