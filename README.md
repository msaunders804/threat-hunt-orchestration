# Threat Hunt Orchestrator (Donut)

A self-hosted FastAPI service that powers **Donut** — an AI threat hunting agent integrated with Obsidian via the [Obsidian Collab Relay](https://github.com/NormalTechGuy/Obsidian-Collab-Relay) bot.

Donut answers threat hunting questions in chat, works through assigned tasks autonomously, and writes findings back to a shared Obsidian vault.

---

## What it does

**Chat queries** — ask Donut anything in the Obsidian chat:
```
@Donut Is 198.51.100.10 malicious?
@Donut Check this router config for vulnerabilities: ...
```

**Autonomous task execution** — assign tasks to Donut via [TaskNotes](https://tasknotes.dev/) and trigger a work session:
```
@Donut review your tasks and begin
```
Donut reads its assigned tasks, works through each one, and writes findings to `Donut Memory/` in the shared vault.

---

## Agents

| Agent | Trigger | What it does |
|---|---|---|
| **IOC Enrichment** | IP addresses, domains, or file hashes | Looks up each indicator and returns reputation, category, and severity |
| **Router Config Analyzer** | Cisco IOS config pasted in message | Audits for ACL gaps, management plane exposure, weak encryption, and hardening misses |

---

## Architecture

```
Obsidian chat
      │  @Donut <message>
      ▼
  Jester bot  ──► POST /api/query
                        │
                        ▼
                   Donut agent  (Claude Sonnet via deepagents)
                   ├─ enrich_iocs
                   ├─ analyze_router_config
                   ├─ read_task_list         ──► TaskNotes/ in shared vault
                   ├─ update_task_status     ──► TaskNotes/ in shared vault
                   ├─ read_knowledge_base    ──► all .md in shared vault
                   ├─ write_hunt_note        ──► Donut Memory/ in shared vault
                   ├─ list_obsidian_vaults
                   └─ set_shared_folder
                        │
                        ▼
               {"summary": "markdown report"}
                        │
                        ▼
              Obsidian chat response
```

---

## Obsidian integration

Donut reads and writes to a shared Obsidian vault synced via Obsidian Relay.

| Folder | Purpose |
|---|---|
| `TaskNotes/` | TaskNotes plugin tasks. Assign to Donut by setting `assignee: donut` in properties. |
| `Donut Memory/` | Hunt notes written by Donut after completing each task. Auto-created on first use. |

### Assigning a task to Donut

Create a task in TaskNotes and set the `assignee` property to `donut`. Donut picks up any task where `assignee: donut` and `status` is not `done`.

### Vault configuration

On first use, configure the shared vault path in chat:
```
@Donut configure your vault
```
Donut will list available Obsidian vaults and save the selection. When the share rotates, run the same command to reconfigure.

---

## Deployment

> **Important:** Donut is a standalone backend service. It must be running before the Jester bot can respond to `@Donut` mentions. Restarting the Jester container does not start Donut — they are separate processes.

### Option 1 — Run locally (recommended for development)

**Requirements:** Python 3.11+, Anthropic API key.

```bash
git clone https://github.com/<you>/threat-hunt-orchestrator.git
cd threat-hunt-orchestrator

python -m venv .venv
.venv\Scripts\Activate.ps1        # Mac/Linux: source .venv/bin/activate

pip install -r requirements.txt

cp .env.example .env
# edit .env — set ANTHROPIC_API_KEY and SHARED_FOLDER
```

Start the server:
```bash
python -m uvicorn main:app --host 0.0.0.0 --port 8000
```

When Donut runs on the host machine and Jester runs in Docker, the bot reaches Donut via `host.docker.internal:8000`. Set this in the Jester bot's `.env`:
```dotenv
PWHL_API_URL=http://host.docker.internal:8000
```

---

### Option 2 — Run in Docker

Build the image:
```bash
docker build -t donut .
```

Run the container, mounting your shared Obsidian vault as a volume:
```bash
docker run -d \
  --name donut \
  -p 8000:8000 \
  -e ANTHROPIC_API_KEY=sk-ant-... \
  -e SHARED_FOLDER=/vault \
  -v "/path/to/Saunders Share:/vault" \
  donut
```

> On Windows, use the full path with forward slashes or quotes:
> ```bash
> -v "C:\Users\msaun\OneDrive\Documents\Roosters\Saunders Share:/vault"
> ```

The `SHARED_FOLDER` env var must match the container-side mount path (`/vault` above, not the Windows path).

---

### Option 3 — Run Donut and Jester in Docker together

Create a `docker-compose.yml` alongside both repos:

```yaml
services:
  donut:
    build: ./threat-hunt-orchestrator
    ports:
      - "8000:8000"
    environment:
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
      - SHARED_FOLDER=/vault
    volumes:
      - "${SHARED_FOLDER}:/vault"

  jester:
    image: your-jester-image
    environment:
      - PWHL_API_URL=http://donut:8000
    depends_on:
      - donut
```

When both containers are on the same Docker network (as above), Jester reaches Donut by container name (`http://donut:8000`) — not `host.docker.internal`.

---

### Verify Donut is running

```bash
curl http://localhost:8000/health
# {"status": "orchestrator alive"}
```

If the Jester bot responds with a connection error, Donut is not running or not reachable on port 8000.

---

## API

### `GET /health`
Container health check. Returns `{"status": "orchestrator alive"}`.

### `POST /api/query`

**Request:**
```json
{ "question": "your question or pasted config", "session_id": "optional-thread-id" }
```

**Response:**
```json
{ "summary": "markdown-formatted findings" }
```

---

## Connecting to Obsidian Collab Relay

The [Jester bot](https://github.com/NormalTechGuy/Obsidian-Collab-Relay) watches for `@Donut` mentions in Obsidian chat and forwards messages to this service.

In the bot's `.env`:
```dotenv
PWHL_API_URL=http://<this-machine-ip>:8000
```

Restart the bot container. No Obsidian plugin changes required.

---

## Project structure

```
main.py                             FastAPI entrypoint
orchestrator/
  client.py                         Anthropic / Bedrock client factory
  graph.py                          Donut agent definition and system prompt
  agents/
    ioc_enrichment.py               IOC lookup sub-agent
    router_config.py                Cisco IOS audit sub-agent
    tools/
      ioc_tools.py                  Raw IOC lookup functions
      config_tools.py               Raw router config functions
      file_tools.py                 Obsidian vault read/write tools
config/
  README.md                         Bedrock swap procedure
.env.example                        Environment variable reference
requirements.txt
```

---

## Bedrock swap

Runs against the Anthropic direct API by default. To switch to AWS GovCloud Bedrock:

```dotenv
INFERENCE_PROVIDER=bedrock
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
AWS_REGION=us-gov-west-1
BEDROCK_MODEL_ID=anthropic.claude-sonnet-4-6-20251114-v1:0
```

See [`config/README.md`](config/README.md) for IAM policy and model ID details.

---

## License

MIT
