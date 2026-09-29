# LLMHound

<p align="center"><strong>Mapping the attack surface of AI infrastructure into BloodHound with OpenGraph.</strong></p>

LLMHound is a BloodHound [OpenGraph](https://bloodhound.specterops.io/opengraph/overview)
collector that remotely maps the attack surface of LLM and agentic AI
infrastructure — MCP servers, A2A agents, LLM gateways, inference servers,
vector stores, model registries, notebooks, and AI UIs — from a central
collection server across your network.

```
one collection server → one network scan → one OpenGraph payload → attack paths in BloodHound
```

> **Status: design phase.** The collector is specified in
> [`docs/plans/2026-09-29-llmhound-design.md`](docs/plans/2026-09-29-llmhound-design.md)
> and not yet implemented. See the milestones section.

## What it finds

| Surface | Collection (v1: anonymous, read-only) |
|---|---|
| **MCP** | Network MCP servers; tools, resources, prompts; public/unauthenticated access evidence |
| **A2A** | Agent cards and advertised skills from `/.well-known/agent-card.json` |
| **Ollama** | Served models, digests, modelfiles, templates, system prompts |
| **vLLM** | Inference server fingerprinting and served models |
| **LiteLLM** | Gateway fingerprinting, model catalog, exposed configuration |
| **Qdrant** | Vector collections, point counts, schema context |
| **MLflow** | Experiments, registered models, artifact stores |
| **Jupyter** | Sessions and workspace files, authentication posture |
| **Open WebUI** | Instance fingerprinting, configured Ollama/Qdrant backends |
| **LangServe** | Application fingerprinting and runnable inventory |

All surfaces are enumerated remotely — LLMHound never collects from the host
it runs on and performs no authenticated requests in v1.

## How it works

1. **Targets** — CIDR ranges and/or a targets file (IPs, FQDNs)
2. **Discovery** — bounded-concurrency port probes plus HTTP path
   fingerprinting identify reachable AI services
3. **Enumeration** — per-surface read-only collection with honest coverage
   outcomes (`complete` / `partial` / `failed`)
4. **Emission** — one OpenGraph payload (JSON, ZIP-streamed for large scans)
   with deterministic node identity
5. **Upload** — schema registration, payload upload, and saved-query import
   to BloodHound CE via the API — or drop the payload into your existing
   automated ingest pipeline

## BloodHound integration

- **Structured graph:** ships an extension definition schema
  (`extension/schema.json`) with `LLMHound`-namespaced node and relationship
  kinds, enabling pathfinding in BloodHound CE (v8+, PostgreSQL backend)
- **Hybrid attack paths:** host nodes bridge by property into your existing
  Active Directory graph, so AD principal compromise paths can continue into
  the AI subgraph
- **Clean lifecycle:** a registered `source_kind` allows bulk deletion of all
  LLMHound data from CE database management
- **Starter queries:** ships saved Cypher searches
  (`extension/saved_searches/`) in SpecterOps Query Library format

See [`docs/reference/graph-model.md`](docs/reference/graph-model.md) for the
full node and edge model.

## Graph model summary

- **Nodes:** `LLMHound_Host`, MCP (`MCPServer`, `MCPTool`, `MCPResource`,
  `MCPPrompt`), A2A (`A2AAgent`, `A2ASkill`), AI services (`OllamaInstance`,
  `VLLMInstance`, `LiteLLMGateway`, `QdrantInstance`, `MLflowServer`,
  `JupyterServer`, `OpenWebUIInstance`, `LangServeApp`), served models
  (`AIModel`), and typed resources (`VectorCollection`, `WorkspaceFile`,
  `ModelArtifact`, `ArtifactStore`)
- **Edges:** topology (`RunsOn`, `ProvidesTool`, `ProvidesResource`,
  `ProvidesPrompt`, `ProvidesModel`, `AdvertisesSkill`, `UsesBackend`,
  `Contains`) and traversable access evidence (`PublicAccess`,
  `UnauthenticatedAccess`)

## Quick start (planned)

```bash
# Scan a range and emit an OpenGraph payload
llmhound scan --cidr 10.0.0.0/8 --targets-file known-ai-hosts.txt \
    --output llmhound-2026-09-29.json

# Register the extension schema, upload, and import saved queries
llmhound upload --server https://bloodhound.corp.example \
    --payload llmhound-2026-09-29.json
```

## Operational model

Designed for a dedicated scanner VM feeding an automated BloodHound ingest
pipeline: scheduled scans, checkpointed and resumable, rate-limited, with an
ingest-valid payload always written even on partial failure.

## Milestones

1. **M1** — Skeleton + graph model + OpenGraph emitter (schema, golden tests)
2. **M2** — Discovery + all ten anonymous enumeration surfaces
3. **M3** — Checkpoint/resume + BloodHound CE API upload + saved queries
4. **M4** *(future)* — Credential-driven enumeration and access evidence
5. **M5** *(future)* — Node/edge description docs + OpenGraph library listing

## Licensing

LLMHound is original code, written from scratch. Reference projects
(AgentHound, ShareHound, OpenHound, Netwrix AIHound) informed behavior only —
no code is derived from them. License selection pending; intended to be
permissive (Apache-2.0/MIT-style) for community-listing eligibility.
