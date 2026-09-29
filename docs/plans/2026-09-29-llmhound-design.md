# LLMHound — Design

**Date:** 2026-09-29
**Status:** Approved

## One-liner

LLMHound is a BloodHound OpenGraph collector that remotely maps the attack
surface of LLM and agentic AI infrastructure — MCP servers, A2A agents, LLM
gateways, inference servers, vector stores, model registries, notebooks, and
AI UIs — from a central collection server across your network.

Target positioning: a listing on the SpecterOps OpenGraph community library
page (`bloodhound.specterops.io/opengraph/library`).

## Problem and scope

BloodHound CE (v8+, PostgreSQL backend) is the existing attack-path analysis
platform. Corporate infrastructure increasingly runs AI services (Ollama,
vLLM, LiteLLM, Qdrant, MLflow, Jupyter, Open WebUI, MCP servers, A2A agents)
that are invisible to SharpHound/AzureHound and unrepresented in the graph.

LLMHound closes that gap with a **remote, network-based collector** — no
host-local collection, no foothold deployment. It runs on a dedicated scanner
VM as part of an automated ingest pipeline that feeds BloodHound CE.

### In scope (v1)

- Remote, anonymous, read-only enumeration of reachable AI services
- OpenGraph payload emission (structured graph: extension definition schema
  + conforming data payload)
- BloodHound CE API integration: schema registration, payload upload,
  saved-query import
- Target discovery from CIDR ranges and targets files
- Checkpoint/resume for interrupted scans
- Hybrid bridging into the existing AD graph (match by property)

### Out of scope (v1)

- Host-local collection (agent configs, instruction files, keychains) —
  rejected; this is a collection-server tool
- Authenticated enumeration / active access validation / reversible mutation
  (credential plumbing arrives in a later milestone)
- BloodHound Enterprise-only features (environments, privilege zones,
  findings, metrics)

## Provenance and licensing posture

**LLMHound contains 100% original code.** Reference projects inform behavior
only; no code is copied from any of them:

| Reference | License | Use |
|---|---|---|
| AgentHound (`adithyan-ak/agenthound`) | Apache-2.0 | Behavioral reference: what to enumerate per surface, identity semantics, coverage-outcome honesty. No code. |
| ShareHound (`p0dalirius/sharehound`) | none (all rights reserved) | Architectural reference: targets/worker pool/checkpoint/zip-stream patterns. No code (mandatory). |
| Netwrix AIHound (`netwrix/AIHound`) | MIT | Reference: CE API client surface (login, `PUT /api/v2/extensions`, `POST /api/v2/file-upload`, saved queries). No code. |
| OpenHound (`SpecterOps/OpenHound`) + `openhound-okta` | — | Reference: what a complete extension ships (schema, saved searches, descriptions, docs). No code. |

Normal public Go dependencies (cobra, `modelcontextprotocol/go-sdk`, etc.)
carry their standard `go.mod` license metadata; nothing in the dependency
graph derives from the reference projects.

## Architecture

Single static Go binary (`llmhound`) deployed on the scanner VM and scheduled
by the existing automated-ingest process.

```
targets (CIDR ranges / targets-file)
  → discovery: worker-pool TCP probe of AI-service ports
      + HTTP path fingerprinting → service typing
  → per-service anonymous enumeration modules:
      MCP (tools/resources/prompts)     [official go-sdk]
      A2A (agent cards / skills)
      Ollama, vLLM, LiteLLM, Qdrant, MLflow, Jupyter, Open WebUI, LangServe
  → raw observations → deterministic graph (SHA-256 objectids)
  → OpenGraph payload emission (JSON; ZIP stream for large scans)
  → BloodHound CE: PUT /api/v2/extensions (register schema),
      POST /api/v2/file-upload (payload), POST /api/v2/saved-queries
  — checkpoint journal throughout, resumable
```

### Pipeline stages

1. **Targets** — parse CIDR ranges and/or a targets file (IPs, FQDNs); dedup;
   optional port expansion.
2. **Discovery** — bounded-concurrency TCP probes against known AI-service
   ports (Ollama 11434, vLLM 8000, MLflow 5000, Jupyter 8888, Qdrant 6333,
   Open WebUI 3000/8080, LiteLLM 4000, MCP/A2A over 80/443/8080 + others);
   HTTP path fingerprinting confirms service type.
3. **Enumeration** — per-surface read-only collection; each module records
   its own coverage outcome (`complete` / `partial` / `failed`).
4. **Graph assembly** — observations become nodes/edges with deterministic
   identity.
5. **Emission** — OpenGraph payload written to disk (and optionally pushed
   via the CE API).
6. **Upload** — schema registration, payload upload, saved-query import.

## Repo structure

```
LLMHound/
├── cmd/llmhound/            # CLI entrypoint (cobra)
├── internal/
│   ├── targets/             # CIDR/file parsing, dedup
│   ├── discovery/           # port probes + path fingerprints → service typing
│   ├── collectors/          # one package per AI surface (original clients)
│   ├── graph/               # node/edge model, identity, opengraph emitter
│   ├── checkpoint/          # scan journal + resume
│   ├── bloodhound/          # CE API client (login/schema/upload/queries)
│   └── worker/              # bounded concurrency, rate limiting
├── extension/
│   ├── schema.json          # OpenGraph extension definition schema
│   └── saved_searches/      # starter Cypher queries (Query Library format)
├── docs/
│   ├── plans/               # design + implementation plans
│   └── reference/           # node/edge descriptions (library-page ready)
├── LICENSE                  # Apache-2.0 (ours)
└── README.md
```

## Graph model

**Namespace:** `LLMHound` · **source_kind:** `LLMHound` (enables clean bulk
deletion of our data in CE database management)

### Node kinds

| Group | Kinds |
|---|---|
| Hosts | `LLMHound_Host` |
| MCP | `LLMHound_MCPServer`, `LLMHound_MCPTool`, `LLMHound_MCPResource`, `LLMHound_MCPPrompt` |
| A2A | `LLMHound_A2AAgent`, `LLMHound_A2ASkill` |
| AI services | `LLMHound_OllamaInstance`, `LLMHound_VLLMInstance`, `LLMHound_LiteLLMGateway`, `LLMHound_QdrantInstance`, `LLMHound_MLflowServer`, `LLMHound_JupyterServer`, `LLMHound_OpenWebUIInstance`, `LLMHound_LangServeApp` |
| Served models | `LLMHound_AIModel` |
| Typed resources | `LLMHound_VectorCollection`, `LLMHound_WorkspaceFile`, `LLMHound_ModelArtifact`, `LLMHound_ArtifactStore` |
| Umbrella | `LLMHound_AIService` (label carried by concrete service nodes; does not own identity) |

Credential nodes are deferred to the credential milestone.

### Edge kinds

- **Topology (non-traversable):** `LLMHound_RunsOn` (service → Host),
  `LLMHound_ProvidesTool`, `LLMHound_ProvidesResource`, `LLMHound_ProvidesPrompt`,
  `LLMHound_ProvidesModel`, `LLMHound_AdvertisesSkill`, `LLMHound_UsesBackend`,
  `LLMHound_Contains` (typed-resource containment)
- **Evidence:** `LLMHound_PublicAccess` (MCPServer → MCPResource read
  anonymously after a denied control — traversable) and
  `LLMHound_UnauthenticatedAccess` (service reachable without credentials —
  traversable) so CE pathfinding produces meaningful paths from principals
  into the AI subgraph

Traversability is deliberately conservative in v1: containment/topology is
not access; only observed access evidence traverses.

### Identity

Deterministic SHA-256 `objectid` per node kind, derived from
kind-specific identity fields (endpoint + stable resource keys). Display
names, timestamps, and mutable descriptions never define identity. Service
resources use the owning service identity plus the resource's stable key
(collection name, model name, workspace path). This is our own expression of
the standard BloodHound identity approach.

### Hybrid AD integration

`LLMHound_Host` nodes emit edges matched **by property** (`name` = FQDN)
against the existing AD `Computer` nodes, so attack paths can bridge from
AD principals into the AI subgraph without duplicating host inventory.

## Scanning behavior (v1: anonymous, read-only)

- **No credentials used.** Enumerate, fingerprint, record. The
  authenticated/validation surface is a later milestone.
- **Bounded:** configurable concurrency, per-host rate limiting, connect and
  response timeouts, bounded page sizes on large enumerations.
- **TLS verification on by default**; `--insecure` opt-out for lab use.
- **Honest coverage:** every surface records `complete` / `partial` /
  `failed` / `truncated` as node/edge properties. Partial scans stay useful
  and never overstate coverage.

## Error handling and resilience

- **Checkpoint/resume:** every completed target/service/result is journaled;
  interrupted scans resume without rescanning completed work.
- **Loss-tolerant:** unreachable targets are recorded as failed surfaces,
  not fatal errors; a module error degrades only that surface.
- **Payload before exit:** an ingest-valid payload is always written, even
  on partial failure — one scan = one uploadable artifact.

## Ingest pipeline

1. `llmhound scan --targets-file hosts.txt --cidr 10.0.0.0/8` →
   `llmhound-<timestamp>.json` (+ optional `.zip`)
2. `llmhound upload --server https://bloodhound.corp --token-file ...`
   registers the extension schema, uploads the payload, imports saved
   queries
3. Scanner VM cron/systemd drives both; your existing automated ingest can
   also pick up the emitted files directly (UI upload or API)

## Testing strategy

- **Unit:** per-collector tests against `httptest` fake services
- **Emission:** golden-file tests for OpenGraph payload output; schema
  conformance validated against the published OpenGraph JSON schemas
- **Checkpoint:** kill/resume determinism tests
- **Integration (optional, CI):** docker-compose CE + PostgreSQL; end-to-end
  upload then Cypher verification of expected nodes/edges

## Milestones

1. **M1 — Skeleton + graph + emitter:** CLI, targets, graph model, OpenGraph
   emission, schema, golden tests
2. **M2 — Discovery + collectors:** port/path discovery and all ten
   anonymous enumeration surfaces
3. **M3 — Checkpoint + upload:** journal/resume, CE API client, saved
   queries, end-to-end against a CE instance
4. **M4 — Credentials (future):** authenticated enumeration and access
   evidence
5. **M5 — Library listing (future):** README polish, node/edge description
   docs, submission PR to the BloodHound docs repo
