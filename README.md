```text
 _     _     __  __ _   _                       _ 
| |   | |   |  \/  | | | | ___  _   _ _ __   __| |
| |   | |   | |\/| | |_| |/ _ \| | | | '_ \ / _` |
| |___| |___| |  | |  _  | (_) | |_| | | | | (_| |
|_____|_____|_|  |_|_| |_|\___/ \__,_|_| |_|\__,_|
```

**Map exposed LLM & agentic-AI infrastructure directly onto your BloodHound attack paths.**

`Go 1.27+` · `Apache-2.0` · `Anonymous & Read-Only` · `15 AI Surfaces` · `BloodHound CE v9.7.1`

---

LLMHound remotely inventories LLM gateways, MCP servers, A2A agents, model runners,
notebooks, AI UIs, and vector databases from a single scanner host. It **only reads**,
**never sends or guesses credentials**, and attaches discovered services to the hosts you
already track in [BloodHound](https://bloodhound.specterops.io/) (from SharpHound and
AzureHound) so the graph can answer:

> *Which hosts along an attack path to tier 0 are running AI services, and which of those are open to anyone?*

New to the project? Read the five-minute **[Executive Summary](docs/00-executive-summary.md)**.

## Why LLMHound

- **Shadow AI sits on existing attack paths.** Unauthenticated notebooks, model servers, and
  agent-tool endpoints are routinely deployed on hosts only one or two hops from tier 0.
- **Context, not a competing inventory.** LLMHound attaches typed service nodes to existing
  BloodHound nodes (`Computer`, `AZVM`, Entra devices) via your asset mapping rather than
  guessing host identity with reverse DNS or suffix rules.
- **Safe to point at internal infrastructure.** Collection is strictly anonymous, bounded in
  requests/bytes/pages, and verifies TLS certificates by default.

## Architecture & pipeline

```text
  +--------------------+
  |   Target Inputs    |  IPs, CIDRs, FQDNs, exclusions (llmhound targets)
  +---------+----------+
            |
            v
  +--------------------+     +-------------------------------------------+
  |   llmhound plan    |     |        Optional Asset Mapping File        |
  | (offline dry-run)  |     | target -> BloodHound object_id + kind     |
  +---------+----------+     +---------------------+---------------------+
            |                                      |
            +------------------+-------------------+
                               |
                               v
  +----------------------------------------------------------------------+
  |                    llmhound scan  /  llmhound resume                 |
  |  TCP Sweep -> Cached HTTP/S Probe -> Attack-Path Collect & Secret Scan |
  +--+----------------+----------------+-------------------+-------------+
     |                |                |                   |
     v                v                v                   v
  *-base.json    *-linking.json   *.evidence.jsonl    *.content.jsonl
  (compact +     (sourceless      (full inventory,    (opt-in full mode;
   source_kind)   native edges)    TLS & redirect log) 0600; no Upload)
     |                |
     +-------+--------+
             |
             v
  +----------------------------------------------------------------------+
  |                          llmhound upload                             |
  |  CE Gate -> Schema -> ZIP/Chunked Base -> Pre-Flight -> Links        |
  +----------------------------------+-----------------------------------+
                                     |
                                     v
                        BloodHound CE + 17 Saved Queries
```

1. **Discover fast.** Stage 1 concurrent TCP sweep (`--tcp-concurrency 512`) eliminates closed ports before HTTP probing, reuses cached responses across shared ports (`8000`, `8080`, `3000`), and auto-upgrades HTTP-to-HTTPS (`--scheme auto`). Default `--profile attack-path` focuses on the 10 highest-value execution, gateway, credential, and store surfaces (`--profile rce-only` narrows to 5; `--profile full` runs all 15).
2. **Keep BloodHound signal-dense.** Default `--graph-mode attack-path` emits `AIService` nodes (with `risk_signals`), cross-host `UsesBackend` edges (`P5`), and high-risk `MCPTool` nodes (`capability_hint` for `P7`), keeping verbose child inventories in `.evidence.jsonl` (`--graph-mode full` emits all child nodes). Target inputs also support `--endpoints-file` (`host:port` lists) and `--prioritize-from-bh` to scan Tier-0-adjacent hosts first.
3. **Redact, never store secrets.** Default `--content-mode secrets-only` scans high-yield configs and notebooks **in memory** with zero `.content.jsonl` disk bloat while flagging `has_exposed_secret = true` (`P8`); `--content-mode full` writes bounded bodies to `0600` `.content.jsonl` with `[secret:<type>]` redaction.
4. **Attach.** Mapped targets emit `ObservedAt` edges to existing native BloodHound nodes in a separate **sourceless** linking payload; unmapped targets fall back to `NetworkEndpoint` (or omit with `--mapped-only`).
5. **Opt-in path rules (off by default).** Traversable `CanExecuteOn` edges require explicit per-rule opt-in (`jupyter-auth-disabled`, `ray-anonymous-jobs`, `langflow-unauthenticated-exec`, `flowise-unauthenticated-exec`), verified native mapping, and assumed-reach principals.

## Supported surfaces

All 15 collectors are implemented and wired through `plan`, `scan`, and `resume`:

| Surface | Default Port | What LLMHound collects (anonymous, read-only, bounded) | Reference |
|---|---:|---|---|
| **Jupyter** | `8888` | Auth posture, API/server version, kernels, sessions, workspace files, bounded text/notebook bodies | [`jupyter`](docs/collectors/jupyter.md) |
| **MCP** | `8080` | Streamable HTTP & SSE server identity, protocol version, tools, resources, prompts, RFC 9728 OAuth metadata, bounded text resource bodies | [`mcp`](docs/collectors/mcp.md) |
| **Ollama** | `11434` | Runtime version, model catalog & digests, running models, bounded `/api/show` modelfiles/prompts/templates | [`ollama`](docs/collectors/ollama.md) |
| **A2A** | `8080` | Agent card metadata, skills, protocol/agent versions, security declarations, sanitized interface refs | [`a2a`](docs/collectors/a2a.md) |
| **vLLM** | `8000` | Runtime version, vLLM-verified served model catalog & aliases (`max_model_len`, `root`, `parent`) | [`vllm`](docs/collectors/vllm.md) |
| **Qdrant** | `6333` | Version/commit, collections, vector schemas, snapshots, bounded payload-only point sampling (no vectors) | [`qdrant`](docs/collectors/qdrant.md) |
| **LiteLLM** | `4000` | OpenAPI fingerprint, gateway version, models, redacted provider/backend refs, bounded config bodies | [`litellm`](docs/collectors/litellm.md) |
| **MLflow** | `5000` | Version, paginated experiments & registered models, stages/aliases, sanitized artifact-store refs, bounded small text artifacts | [`mlflow`](docs/collectors/mlflow.md) |
| **Open WebUI** | `3000` | Version, auth/signup posture, exposed models, sanitized backend URLs, bounded config snapshots | [`open_webui`](docs/collectors/open_webui.md) |
| **LangServe** | `8000` | OpenAPI runnable routes, playground exposure, bounded runnable input/output/config schemas | [`langserve`](docs/collectors/langserve.md) |
| **OpenAI-compatible** | `8000` | Generic fallback (only when specific runtimes on the same host:port do not match): served models and server identity headers | [`openai_compatible`](docs/collectors/openai_compatible.md) |
| **Ray Dashboard** | `8265` | Ray version/commit, cluster summary, anonymous job/actor listings, bounded job entrypoints & env capture | [`ray`](docs/collectors/ray.md) |
| **Langflow** | `7860` | Version, auto-login posture, flow & component inventories, bounded flow bodies | [`langflow`](docs/collectors/langflow.md) |
| **Flowise** | `3000` | Version, chatflow inventory, public-chatflow flags, bounded flow definitions | [`flowise`](docs/collectors/flowise.md) |
| **ChromaDB** | `8000` | Version/heartbeat, tenant/database/collection inventory, item counts, bounded document sampling (no embeddings) | [`chromadb`](docs/collectors/chromadb.md) |

## Quick start

Requires **Go 1.27+** (pinned in [`go.mod`](go.mod)).

### 1. Build and plan offline

```bash
CGO_ENABLED=0 go build -o llmhound ./cmd/llmhound
cp llmhound.example.yaml llmhound.yaml   # set scope, vantage_key, user_agent contact, targets

./llmhound targets --config llmhound.yaml # normalize + deduplicate targets (zero traffic)
./llmhound plan    --config llmhound.yaml # inspect targets x checks before sending a packet
```

### 2. Scan (with optional asset mapping)

Supply an asset-mapping JSON/CSV file from your asset-inventory or normalization pipeline to
link discovered services directly to existing BloodHound nodes:

```json
{
  "source": "inventory-2026-11-21",
  "mappings": [
    {"target": "ai1.corp.example", "object_id": "S-1-5-21-...-1103", "kind": "Computer"},
    {"target": "10.1.2.3",         "object_id": "/SUBSCRIPTIONS/.../VIRTUALMACHINES/AI-VM1", "kind": "AZVM"}
  ]
}
```

```bash
./llmhound scan --config llmhound.yaml \
  --mapping-file assets.json \
  --output-dir ./out --prefix scan1

# Interrupted? Resume from the checkpoint journal without re-scanning completed surfaces:
./llmhound resume --config llmhound.yaml \
  --journal ./out/scan1.journal.jsonl \
  --mapping-file assets.json \
  --output-dir ./out --prefix scan1
```

### 3. Output files written under `./out`

| File | Contents | Ship to BloodHound? |
|---|---|---|
| `scan1-base.json` (or `scan1.json` if unmapped) | LLMHound-owned subgraph (`source_kind: LLMHound`) | Step 1 |
| `scan1-linking.json` | Edges to existing native nodes (**deliberately no** `source_kind`) | Step 2 (after pre-flight) |
| `scan1.evidence.jsonl` | Per-check outcomes, fingerprints, TLS, redirects, correlation decisions | Audit sidecar (keep local) |
| `scan1.content.jsonl` | Bounded content bodies with `[secret:<type>]` redaction (mode `0600`) | **Never** ship to BloodHound |
| `scan1.journal.jsonl` | Append-only crash-safe checkpoint journal for `llmhound resume` | Keep for resume/audit |

### 4. Upload to BloodHound CE (v9.7.1)

`llmhound upload` runs the CE adapter validation gate first, registers the OpenGraph schema,
uploads the base subgraph, runs a read-only Cypher existence pre-flight on any native
targets (skipping missing or kindless stub nodes), uploads the sourceless linking payload,
and imports all **15 saved queries (`P1`–`P8`, `I1`–`I7`)**:

```bash
export BLOODHOUND_URL="http://127.0.0.1:8080"
export BLOODHOUND_TOKEN_ID="..."
export BLOODHOUND_TOKEN_KEY="..."

./llmhound upload --validate-only
./llmhound upload --register-schema \
  --base-file ./out/scan1-base.json \
  --linking-file ./out/scan1-linking.json \
  --import-queries
```

> **Why the two-step upload matters:** BloodHound CE tags every node referenced in a
> `source_kind` payload and deletes tagged nodes during source cleanup; missing link
> targets create empty stub nodes. Always upload via `llmhound upload` (or ingest `base`
> first, verify targets, then ingest `linking` without `source_kind`).

Full CLI flags, YAML schema, and mapping formats: [`configuration.md`](docs/guides/configuration.md).

## Responsible use

LLMHound actively probes HTTP endpoints. **Run it only against networks and systems you own
or are explicitly authorized to assess.** Always run `llmhound plan` first, maintain an
`exclude` list, and set an identifiable `user_agent` carrying operator contact details (as
shown in [`llmhound.example.yaml`](llmhound.example.yaml); the fallback default is
`LLMHound/dev`). Treat all scraped tool/skill descriptions, banners, and `.content.jsonl`
bodies as **untrusted attacker-controlled input**, and protect scan artifacts with strict
file permissions and retention controls.

## Documentation

Start at the **[documentation index](docs/README.md)** for a guided reading path:
[Executive Summary](docs/00-executive-summary.md) ·
[Design](docs/01-design.md) ·
[Graph Model](docs/02-graph-model.md) ·
[Collector Capabilities](docs/03-collector-capabilities.md) ·
[Saved Queries](docs/04-saved-queries.md) ·
[CE Compatibility](docs/05-ce-compatibility.md) ·
[Roadmap](docs/06-roadmap.md) ·
[Decision Log](docs/07-decisions.md).

## Contributing & verification

See the [development guide](docs/guides/development.md) for the reproducible BloodHound CE
Docker lab ([`lab/`](lab/README.md)), CI rules, and tests:

```bash
gofmt -l . && go vet ./... && go test -race ./...
```

Note: real-environment / production deployment testing has not yet been performed; all
surface collectors and CE API workflows are verified against local `httptest` fixtures and
the pinned Docker CE 9.7.1 lab. AI coding agents should read [`AGENTS.md`](AGENTS.md) first.

## Licensing

Apache-2.0 ([`LICENSE`](LICENSE)). LLMHound is 100% original Go code; reference projects
(`AgentHound`, `ShareHound`, `OpenHound`, `Netwrix AIHound`) informed behavior and schema
design only, with zero copied code. See [provenance](docs/01-design.md#provenance-and-licensing-posture).
