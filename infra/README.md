# Test infrastructure (home-lab)

Stand up a real Elasticsearch + Kibana + Ollama environment to exercise the
orchestrator's `ES_MODE=live` and `INFERENCE_PROVIDER=ollama` paths.

Target: a 32 GB mini PC (CPU-only is fine). Budget roughly ES 4 GB + Kibana
~1 GB + one 7–8B SLM ~6 GB — comfortable at 32 GB.

---

## 1. Elasticsearch + Kibana

```bash
cd infra
cp .env.example .env          # edit STACK_VERSION + passwords
docker compose up -d
# wait ~1 min; Kibana at http://<mini-pc>:5601  (login: elastic / ELASTIC_PASSWORD)
```

If ES exits on boot with a `vm.max_map_count` error (Linux host):
```bash
sudo sysctl -w vm.max_map_count=262144      # persist in /etc/sysctl.conf
```

### Point the orchestrator at it

In the repo-root `.env`:
```dotenv
ES_MODE=live
ES_URL=http://<mini-pc>:9200
ES_USERNAME=elastic
ES_PASSWORD=<ELASTIC_PASSWORD>
```

Or use an API key (preferred — no password in the app config):
```bash
curl -u elastic:$ELASTIC_PASSWORD -X POST http://<mini-pc>:9200/_security/api_key \
  -H 'Content-Type: application/json' \
  -d '{"name":"threat-hunt-orch"}'
# → {"id":"...","api_key":"..."}  encode as id:api_key
```
```dotenv
ES_API_KEY=<id>:<api_key>
```

### Verify the field contract (before a full hunt)
```bash
python scripts/verify_es_contract.py
```
Runs the exact queries `LiveESClient` uses and prints results. Empty is fine if
data isn't flowing yet; errors mean an auth/connectivity/field-mapping issue.

---

## 2. Data ingest (Beats)

The orchestrator expects ECS fields. Defaults line up with Beats index names
(`packetbeat-*`, `winlogbeat-*`); override via `ES_FLOW_INDEX` / `ES_EVENT_INDEX`.

| Source | Runs on | Feeds | Key ECS fields |
|---|---|---|---|
| **Packetbeat** (`packetbeat.yml`) | mini PC (LAN NIC) | top-talkers, DNS IOC hits | `source.ip`, `source.bytes`, `destination.ip`, `dns.question.name` |
| **Winlogbeat** (`winlogbeat.yml`) | Windows endpoints (+ Sysmon) | endpoint IOC hits (hashes) | `file.hash.*`, `process.*` |
| **Zeek** (optional) | mini PC | richer conn/dns/files | via Filebeat's Zeek module |

- Edit `MINI_PC_IP` and credentials in the Beats YAMLs.
- Packetbeat needs raw-capture privileges — run natively (`sudo packetbeat -e -c packetbeat.yml`) or containerized with `network_mode: host` + `cap_add: [NET_ADMIN, NET_RAW]`.
- **Zeek**: easiest path is Zeek writing JSON logs + Filebeat's built-in `zeek` module (`filebeat modules enable zeek`), which maps to ECS `zeek-*` / `source.*`/`destination.*`. Then set `ES_FLOW_INDEX=packetbeat-*,filebeat-*`.

To generate traffic for testing: browse, run `nmap`/`fping` on the LAN, or curl a
few of the IOC hosts referenced in `data/ioc_mock.json` so they show up in DNS/flows.

---

## 3. Ollama (hybrid: router local, heavy roles frontier)

```bash
# on the mini PC
curl -fsSL https://ollama.com/install.sh | sh      # or the Windows installer
ollama pull qwen2.5:7b       # strong structured-output / tool-calling for its size
ollama pull llama3.1:8b      # alternative
```

The orchestrator can keep frontier models for the reasoning-heavy roles (vuln
triage, Sigma authoring, synthesis) and run only routing locally. In repo-root
`.env`:

```dotenv
# Provider defaults to anthropic (frontier) for all roles...
INFERENCE_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-...
```

Per-role local override requires pointing a role at Ollama. Since roles resolve
their *model id* but share one provider, the simplest hybrid is either:

- **All-frontier now, prove Ollama separately** (recommended first step):
  ```bash
  INFERENCE_PROVIDER=ollama DIRECT_MODEL=qwen2.5:7b OLLAMA_BASE_URL=http://<mini-pc>:11434 \
      python scripts/smoke_hunt.py      # confirm one clean end-to-end hunt
  ```
- **True per-role split across providers**: this needs a small enhancement to the
  factory (provider-per-role, not just model-per-role). Ask and I'll add it — it's
  a ~15-line change to `orchestrator/llm.py` + `config.py`.

> Note: `parse` is deterministic (no LLM). The only genuinely "light" LLM role is
> `router`, and routing is mostly heuristic — so the highest-value local test is
> running `synthesis` on the SLM and comparing report quality.

---

## Resource tips (32 GB, CPU-only)
- ES heap: `ES_HEAP=4g` (don't exceed 50% of the container's RAM).
- Run one SLM at a time; 7–8B on CPU is a few tok/s — fine for testing, slow for volume.
- If RAM gets tight, stop Kibana (`docker compose stop kibana`) — the orchestrator
  only needs ES.
