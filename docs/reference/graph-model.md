# LLMHound graph model

LLMHound emits a BloodHound OpenGraph data payload conforming to the
extension definition schema in `extension/schema.json`. Every node uses a
deterministic `objectid`; the extension namespace and `source_kind` are both
`LLMHound`.

Status: **draft** — implements the approved design in
[`docs/plans/2026-09-29-llmhound-design.md`](../plans/2026-09-29-llmhound-design.md).

## Nodes

| Group | Kinds |
|---|---|
| Hosts | `LLMHound_Host` |
| MCP | `LLMHound_MCPServer`, `LLMHound_MCPTool`, `LLMHound_MCPResource`, `LLMHound_MCPPrompt` |
| A2A | `LLMHound_A2AAgent`, `LLMHound_A2ASkill` |
| AI services | `LLMHound_OllamaInstance`, `LLMHound_VLLMInstance`, `LLMHound_LiteLLMGateway`, `LLMHound_QdrantInstance`, `LLMHound_MLflowServer`, `LLMHound_JupyterServer`, `LLMHound_OpenWebUIInstance`, `LLMHound_LangServeApp` |
| Served models | `LLMHound_AIModel` |
| Typed resources | `LLMHound_VectorCollection`, `LLMHound_WorkspaceFile`, `LLMHound_ModelArtifact`, `LLMHound_ArtifactStore` |
| Umbrella | `LLMHound_AIService` |

Concrete AI-service nodes also carry the `LLMHound_AIService` label. The
umbrella label exists for queries and does not own identity.

- `LLMHound_Host` represents one scan target (IP or FQDN). It is the bridge
  point for hybrid attack paths: edges matched by property (`name` = FQDN)
  can connect existing Active Directory `Computer` nodes into the AI
  subgraph.
- `LLMHound_AIModel` is a model served by a runtime such as Ollama or vLLM.
  A persisted MLflow model version is a `LLMHound_ModelArtifact`, not an
  `AIModel`.
- `LLMHound_VectorCollection` represents a Qdrant collection. Individual
  bounded point references are retained as properties, not as nodes, in v1.
- `LLMHound_WorkspaceFile` represents a Jupyter notebook or file reachable
  through the Jupyter contents API.
- `LLMHound_ArtifactStore` represents a safely canonicalized physical
  storage root reported by MLflow (bucket, container, filesystem, or DBFS
  root).

## Identity

- Every node kind uses a deterministic SHA-256 `objectid` derived from
  kind-specific identity fields: the owning service endpoint plus the
  resource's stable key (exact collection name, model name, reported
  workspace path, or registered model name and version).
- Display names, timestamps, and mutable descriptions never define identity.
- Repeated observations of the same endpoint are idempotent: same identity,
  merged properties.

## Edges

### Topology (non-traversable)

Containment and provision relationships are evidence of structure, not
access, and do not traverse.

| Edge | Source → target | Meaning |
|---|---|---|
| `LLMHound_RunsOn` | service → `LLMHound_Host` | The service was observed listening on this host |
| `LLMHound_ProvidesTool` | `LLMHound_MCPServer` → `LLMHound_MCPTool` | Tool enumerated from the server |
| `LLMHound_ProvidesResource` | `LLMHound_MCPServer` → `LLMHound_MCPResource` | Resource enumerated from the server |
| `LLMHound_ProvidesPrompt` | `LLMHound_MCPServer` → `LLMHound_MCPPrompt` | Prompt enumerated from the server |
| `LLMHound_ProvidesModel` | service → `LLMHound_AIModel` | Model served by a runtime |
| `LLMHound_AdvertisesSkill` | `LLMHound_A2AAgent` → `LLMHound_A2ASkill` | Skill advertised in the agent card |
| `LLMHound_UsesBackend` | service → service | Explicit configured dependency (e.g., Open WebUI → Ollama) |
| `LLMHound_Contains` | service → typed resource | Typed-resource containment (Qdrant collections, MLflow artifacts, Jupyter workspace files) |

### Access evidence (traversable)

Only observed access evidence traverses, so BloodHound pathfinding produces
paths grounded in proof rather than topology.

| Edge | Source → target | Meaning |
|---|---|---|
| `LLMHound_PublicAccess` | `LLMHound_MCPServer` → `LLMHound_MCPResource` | The resource was read anonymously after an unauthenticated control read was denied |
| `LLMHound_UnauthenticatedAccess` | `LLMHound_Host` → service | The service accepted enumeration without credentials |

## Coverage properties

Every enumerated surface records an honest outcome as node/edge properties:

- `coverage`: `complete` / `partial` / `failed` / `truncated`
- `collected_at`: observation timestamp
- `endpoint`: canonical host:port the observation came from

Partial evidence remains useful and is never overstated as complete.

## Reserved for future milestones

- `LLMHound_Credential` nodes and credential-bearing edges (M4)
- Differential credential-to-resource access evidence (M4)
