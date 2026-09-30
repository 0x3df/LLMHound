# LLMHound graph model

> **Status: revised draft.** Companion to the
> [design plan](../plans/2026-09-29-llmhound-design.md). Nothing is implemented
> yet. Names below are proposed; the OpenGraph adapter and extension schema
> must be validated against the exact target BloodHound release.

LLMHound collects AI-infrastructure observations for BloodHound and downstream
inventory enrichment through anonymous, bounded, read-only collection.
The planned extension/source identifier and
`source_kind` remain `LLMHound`; node and edge kinds use clean logical names.

## Naming contract

- **Kinds:** use `OllamaInstance`, `MCPServer`, `ObservedAt`, and similar names
  below without a blanket collector prefix. The M0 spike records whether the
  target CE requires any qualification in [ce-compatibility.md](ce-compatibility.md).
- **Display names:** describe the instance, for example
  `Ollama · ai-server-01:11434`, without a collector prefix.
- **Ownership:** retain `LLMHound` in extension/source metadata. Cleanup must
  use validated source ownership, never a kind-name prefix.
- **Adapter mapping:** verify whether the target OpenGraph schema isolates kinds
  by extension or uses a global kind namespace. Do not assume generic names
  are collision-free (the observed-target kind is `NetworkEndpoint`, not
  `Host`, for this reason) or reuse another extension's kind merely
  because its spelling matches. Apply minimal qualification only where needed
  for schema requirements or collisions, and document the mapping centrally.
  Schema definitions, emitted payloads, and saved queries must use that mapping.
- **Identity:** the versioned identity tuple includes the stable source identifier,
  deployment scope, and logical kind. Adapter qualification and display-name
  changes do not change object IDs. Source identity prevents cross-collector
  collisions without putting collector branding in every kind.

These are proposed logical names, not a claim that every unqualified name is
accepted by the target BloodHound release. Adapter tests must cover collisions
and consistent kind mapping before declaring support.

## At a glance

All arrows below represent **non-traversable evidence or topology**, scoped
to the recorded collection vantage and operation.

```mermaid
graph TD
    V[Collection vantage] -. UnauthenticatedAccess .-> W[Open WebUI endpoint]
    V -. UnauthenticatedAccess .-> M[MCP endpoint]
    V -. PublicAccess .-> R[MCP resource]
    M -. ProvidesResource .-> R
    M -. ProvidesTool .-> T[MCP tool]
    W -. UsesBackend .-> O[Ollama endpoint]
    O -. ProvidesModel .-> AI[Served model]
    W -. ObservedAt .-> C[Existing AD Computer]
    M -. ObservedAt .-> C
    O -. ObservedAt .-> N[NetworkEndpoint<br/>uncorrelated target]
    AD[Existing AD attack paths] --> C
```

Correlated targets attach to the `Computer` nodes already in BloodHound, so
AI services appear on machines that existing AD attack paths reach.
Correlation is neither an access grant nor a traversable attack transition.

## Nodes

| Group               | Kinds                                                                                                                                      |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| Observation context | `CollectionVantage`                                                                                                                        |
| Observed targets    | existing AD `Computer` (correlated, not emitted), `NetworkEndpoint` (fallback)                                                             |
| MCP                 | `MCPServer`, `MCPTool`, `MCPResource`, `MCPPrompt`                                                                                         |
| A2A                 | `A2AAgent`, `A2ASkill`                                                                                                                     |
| AI services         | `OllamaInstance`, `VLLMInstance`, `LiteLLMGateway`, `QdrantInstance`, `MLflowServer`, `JupyterServer`, `OpenWebUIInstance`, `LangServeApp` |
| AI services (M2c)   | `OpenAICompatibleEndpoint`, `RayDashboard`, `LangflowInstance`, `FlowiseInstance`, `ChromaInstance`                                        |
| Served models       | `AIModel`                                                                                                                                  |
| Typed resources     | `VectorCollection`, `WorkspaceFile`, `ModelArtifact`, `ArtifactStore`                                                                      |
| Umbrella label      | `AIService`                                                                                                                                |

In the edge tables, **service** means an MCP server, A2A agent, or AI-service
endpoint, not its child tools, skills, or resources.

### Observation context and targets

- **`CollectionVantage`** identifies a configured scanner/network
  context. Its stable key is operator-supplied and scoped to the deployment;
  scan IDs and timestamps are not its identity. Different network contexts
  must not share a vantage key. It is not an attacker principal.
- **`Computer`** (existing AD node, not emitted by LLMHound) is the
  preferred `ObservedAt` target when correlation succeeds; see
  [Computer correlation](#computer-correlation).
- **`NetworkEndpoint`** is the fallback for an observed IP or FQDN target
  that did not correlate. It is not necessarily an authoritative machine and
  may identify a proxy, load balancer, or shared address. Retain the original
  target, normalized hostname, resolved addresses, and observation time
  without claiming that DNS resolution proves identity.
- IP and FQDN `NetworkEndpoint` nodes are not automatically merged with each
  other; ambiguous candidates remain unresolved.

### Services

- **`MCPServer`** represents a fingerprinted network MCP endpoint.
  Enumerated tools, resources, and prompts become their respective child nodes.
- **`A2AAgent`** represents an agent advertised by an agent card;
  advertised skills become `A2ASkill` nodes. Advertisement is not
  evidence of successful invocation.
- **`OpenAICompatibleEndpoint`** (M2c) represents an endpoint that exposes an
  OpenAI-compatible API shape when no specific product (vLLM, LiteLLM,
  llama.cpp, TGI, …) can be proven. It is the honest default, not a guess.
- **AI service kinds** each represent a fingerprinted service endpoint, not a
  guaranteed unique process or installation. Multiple endpoints may eventually
  be correlated to one deployment without rewriting observation identity.
- **`AIService`** is a proposed extra label for concrete AI-service
  nodes, not a separate node or identity component. Validate multi-kind support
  in the target adapter; queries must not depend on unverified support.
- An advertised backend URL alone does not establish its product or availability.
  Keep it as a sanitized dependency reference until independently fingerprinted;
  only then emit a typed service-to-service `UsesBackend` edge. Never scan a
  backend merely because it was advertised; normal target authorization applies.

### Models and resources

- **`AIModel`** is a model served by a runtime, scoped to that service.
  Record a digest when available; a mutable model tag is not immutable content.
- **`VectorCollection`** is a Qdrant collection. Individual point
  references, if collected, remain bounded properties rather than nodes in v1.
- **`WorkspaceFile`** is a Jupyter notebook/file reported by the contents
  API. Listing a path is distinct from successfully reading its content.
- **`ModelArtifact`** is a registered MLflow model version.
- **`ArtifactStore`** is a reported storage root. Bucket names and
  filesystem paths do not establish access or global uniqueness; v1 scopes these
  nodes to the reporting service. Shared-store resolution belongs downstream.

## Identity and correlation contract

Use SHA-256 over an unambiguously serialized, versioned identity tuple. Every
identity includes the source identifier, deployment/tenant scope, and concrete
logical node kind. Scope is
stable configuration, not a secret or a per-scan UUID.

| Node                 | Additional identity fields                                                 |
| -------------------- | -------------------------------------------------------------------------- |
| Collection vantage   | Configured stable vantage key                                              |
| NetworkEndpoint      | Normalized target type and target value                                    |
| Service              | Canonical endpoint: scheme, hostname/IP, effective port, service base path |
| Child resource/model | Owning service ID and exact stable resource key                            |

Resource keys include collection name, model name, MCP resource URI/tool name,
workspace path, or registered model name and version. Preserve case where the
protocol is case-sensitive. Normalize DNS case and IP representation; define
and test default-port and base-path handling. Do not collapse distinct virtual
hosts or path-mounted services. Credentials, fragments, request query strings,
display names, versions, timestamps, and descriptions do not enter endpoint
identity. Endpoints distinguishable only by excluded secret/query material need
an explicit non-secret configured instance key, not a lossy silent merge.

Repeated observations of the same identity retain its ID. This does not prove
that an IP-backed installation stayed the same over time. Preserve temporal
observations rather than treating endpoint identity as a permanent machine ID.

## Computer correlation

LLMHound extends an existing BloodHound buildout: observed targets dedup
against AD `Computer` nodes rather than creating a parallel host graph.

| Precedence | Source | Matches on | Notes |
|---|---|---|---|
| 1 | Operator mapping file | target → Computer objectid/SID | Exact; the only IP-only path besides reverse DNS |
| 2 | AD domain-suffix FQDN | Computer `name`/`dNSHostName` | Only for FQDNs inside configured suffixes; requires M0-confirmed property-matched edge endpoints |
| 3 | CE API lookup (M3) | exact objectid resolved pre-scan | Optional; needs a read-only CE token |
| — | Reverse DNS (opt-in) | PTR → FQDN, then rule 2 | Off by default; recorded as a weaker method |

- A correlated target emits `ObservedAt` (service → `Computer`) with
  `match_method`, `match_value`, and `confidence` edge properties. No
  `NetworkEndpoint` node is created for it.
- No match, suffix mismatch, or several candidate Computers → fallback
  `NetworkEndpoint`; ambiguous candidates and the reason are written to the
  evidence sidecar.
- Correlation is an **edge to an existing node, not an identity merge**.
  Service objectids never depend on it, native BloodHound IDs are never
  overwritten, and LLMHound cleanup never removes or modifies `Computer` nodes.
- A rescan that newly correlates a target attaches to the Computer; the old
  `NetworkEndpoint` is left for the ingest lifecycle policy to retire.

## External asset references

Allow source-qualified external asset references supplied by the ingest pipeline
(e.g. source deployment plus Axonius asset ID, BloodHound node ID, AD SID, or
cloud instance ID). Record mapping method, time, and confidence separately.
LLMHound does not discover these identifiers unless an authorized source exposes
them. FQDN/name matches are candidates, not unconditional identity merges.
Never overwrite native BloodHound identifiers with LLMHound hashes.

## Edges

### Topology (non-traversable)

| Edge               | Source → target          | Meaning                                                                                 |
| ------------------ | ------------------------ | --------------------------------------------------------------------------------------- |
| `ObservedAt`       | service → Computer / NetworkEndpoint | Fingerprinted endpoint was observed through this target (correlated Computer or fallback) |
| `RunsOn`           | service → Computer / NetworkEndpoint | Reserved for supported runtime placement; listening at an address alone is insufficient |
| `ProvidesTool`     | MCPServer → MCPTool      | Tool enumerated, not executed                                                           |
| `ProvidesResource` | MCPServer → MCPResource  | Resource enumerated, not necessarily read                                               |
| `ProvidesPrompt`   | MCPServer → MCPPrompt    | Prompt enumerated                                                                       |
| `ProvidesModel`    | service → AIModel        | Model advertised by the runtime; inference not implied                                  |
| `AdvertisesSkill`  | A2AAgent → A2ASkill      | Skill advertised, not invoked                                                           |
| `UsesBackend`      | service → service        | Explicit dependency reported by the source, not proof of backend access                 |
| `Contains`         | service → typed resource | Collection, workspace, model artifact, or reported artifact store association           |

### Access observations (also non-traversable in v1)

| Edge                    | Source → target                 | Meaning                                                                          |
| ----------------------- | ------------------------------- | -------------------------------------------------------------------------------- |
| `UnauthenticatedAccess` | CollectionVantage → service     | A specific enumeration operation succeeded without credentials from this vantage |
| `PublicAccess`          | CollectionVantage → MCPResource | A specific resource read succeeded without credentials from this vantage         |

`PublicAccess` means anonymous access from the recorded vantage, **not internet
exposure**. A denied control read is not required to record a successful anonymous
read. Neither edge represents arbitrary API use, code execution, or control of
the service. Preserve operation-level evidence; an HTTP 200 login page is not
successful enumeration. Different operations may have different access outcomes.

The earlier host-to-service access edge is intentionally replaced: the collector
observed scanner access, not access originating from the hosting machine.
The graph still supports exposure and inventory queries without enabling these
edges in attack-path search.

Topology and identity mappings remain non-traversable regardless of the
metadata attached to their endpoints.

## Evidence and enrichment contract

These are logical fields; the adapter must define schema-supported serialization
rather than assuming arbitrary nested properties work in OpenGraph. Graph
properties stay flat and queryable (driven by the
[saved queries](saved-queries.md)). Bounded structured evidence that graph
properties cannot represent goes to the `.evidence.jsonl` sidecar emitted with
each payload; graph entries reference it by stable evidence ID.

| Field group         | Required meaning                                                                                                   |
| ------------------- | ------------------------------------------------------------------------------------------------------------------ |
| Provenance          | Schema version, deployment scope, scan ID, collector/version, evidence ID, source and vantage                      |
| Timing              | Observation time in UTC; first/last seen when maintained by a stateful owner                                       |
| Endpoint            | Canonical scheme/host/port/base path plus observed address and sanitized original target                           |
| Fingerprint         | Product/vendor, reported version when available, raw non-secret version text, identification method and confidence |
| Access              | Operation, target, anonymous authentication context, success/denied/unknown outcome, bounded supporting evidence   |
| Dependencies        | Reported backend/storage references, reporting source, and whether independently observed                          |
| Correlation         | Computer match method/value/confidence, or fallback reason and ambiguous candidates                                |
| External references | Source-qualified asset IDs and mapping provenance when supplied                                                    |
| Coverage            | Collection surface, outcome, truncation limits, and failure reason where applicable                                |

Missing version information is **unknown**, not a guessed version. Record
conflicting fingerprints rather than silently selecting whichever observation
arrived last. Every collector must attempt documented version discovery and
record its outcome; successful version discovery is not guaranteed.

### Expanded metadata contract

The [collector capability matrix](collector-capabilities.md) defines required
checks, default metadata collection, and optional sensitive reads for every
surface. Enrichment stays on existing nodes and evidence records; it does not
require new node kinds for every header, version, or check.

- **Component versions:** preserve `product`, `vendor`, `software_version_raw`,
  optional normalized `software_version`, `build_id`, `commit`, and `image_digest`
  when explicitly reported. Store `api_version` and `protocol_version` separately.
  Each value retains its component/endpoint, source field/operation, confidence,
  and observation time. A proxy banner is not a backend version.
- **Capabilities:** MCP tools retain bounded descriptions, input schemas, and
  advertised annotations; resources retain URI schemes/templates; A2A skills
  retain advertised descriptions and security requirements. Label these values
  as declarations, not observed behavior. Bound nested schemas and descriptions.
- **Models/artifacts:** retain reported model family, format, quantization, size,
  digest, alias, upstream artifact/repository reference, and registry lifecycle
  metadata. Keep reported alias-to-backend mappings separate from verified
  identity. Software versions, registry versions, and model digests are distinct.
- **Deployment/dependencies:** preserve explicitly reported instance/deployment
  identifiers and backend/provider/storage references, with provenance and
  independent-observation status. Sanitize references without following them.
- **TLS/endpoints:** retain leaf certificate fingerprint, issuer, subject/SANs,
  validity, verification result/reason, negotiated TLS version when available,
  and authorized redirect observations. Record an insecure override separately;
  it is not successful verification. Certificate sharing never merges assets.

These fields are optional values with explicit availability, not a requirement to
invent metadata a product does not expose. Logical field serialization follows
the schema-supported evidence contract above.

### Per-check results

Each configured check records `check_id`, target, scan ID, vantage, operation,
sanitized source, observation time, outcome, reason, and evidence references.
Outcomes are `success`, `denied`, `unsupported`, `failed`, or `skipped`, as defined
in the capability matrix. Keep them separate from enumeration coverage: a
successful listing can still be truncated. A 404 alone is not proof of an
unsupported feature, and missing optional version data can coexist with a
successful metadata response.

Retain operation-specific access outcomes rather than overwriting one global
anonymous-access flag. Negative/unknown results belong in evidence records,
not positive access edges. Preserve sufficient metadata to compare versions,
backend references, model digests, and inventories across compatible scan scopes
and vantages without treating failed collection as disappearance. (A comparison
tool itself is deferred; v1 only retains the data.)

Use allowlisted metadata and bounded evidence summaries. Strip credentials,
authorization headers, URL userinfo, signed query parameters, and other secrets.
Do not retain full response bodies by default. Sensitive prompts, configuration,
and workspace contents need explicit collection/retention controls; metadata
should remain useful without them. These safeguards apply to checkpoints and
logs as well as exported payloads.

### Coverage and lifecycle

Coverage is per collection surface and operation, not a blanket claim that the
service or host has been completely assessed:

- `complete`: the configured collection surface was fully enumerated.
- `partial`: some operations failed; successful observations remain valid.
- `truncated`: a configured size/page bound stopped enumeration; retain any
  additional errors and limit details separately.
- `failed`: the attempted surface could not be enumerated, including an
  unreachable endpoint. Discovery failures do not create fingerprinted services.

Rescans must not turn old success into fresh success. Keep the last successful
observation separate from the latest attempt and its outcome. Absence from a
partial/failed scan is not deletion or remediation. A complete listing can retire
missing children only within that listing's scope. Freshness/expiry and stale-edge
removal require an explicit ingest reconciliation policy, validated against CE;
a new upload must not be assumed to remove old data automatically.

## Source ownership

Removing collector-owned data must not delete native AD/Azure nodes or unrelated
source data. External integrations own the lifecycle of their own records.

## Implementation acceptance checks

- Golden identity tests cover scope separation, case-sensitive resource keys,
  virtual hosts, path-mounted services, repeat scans, and IP/FQDN ambiguity.
- Anonymous-read and enumeration fixtures preserve operation and vantage;
  login pages, denied operations, and advertised tools do not become capabilities.
- Reverse-proxy observations emit `ObservedAt`, not unsupported `RunsOn`.
- Correlation fixtures cover mapping-file match, AD-suffix match, suffix
  mismatch, ambiguous candidates, IP-only without opt-in, and a rescan that
  newly correlates; service IDs never change and cleanup never touches `Computer`.
- Unknown versions and conflicting observations survive emission honestly;
  component, API/protocol, and model versions remain distinct.
- Capability-matrix fixtures preserve per-check outcomes, declared metadata,
  model provenance, TLS verification/override distinctions, and scoped redirects.
- Secret redaction, size limits, and unauthorized backend-following tests cover
  exports, logs, and checkpoints.
- Lifecycle fixtures cover failed rescans, complete versus partial listings,
  stale observations, and source-isolated cleanup.
- Against a pinned CE release, validate payload/schema, kinds and property types,
  edge endpoint resolution, non-traversability, repeat ingest, and cleanup.
  Demonstrate AI services attached to existing AD Computers while retaining
  non-traversable semantics.

## Reserved for future milestones

- Credential-driven enumeration and credential-to-resource access evidence (M4).

- Per-kind property reference and description pages (M5).
