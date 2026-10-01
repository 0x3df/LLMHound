# LLMHound — Design

**Date:** 2026-09-29
**Status:** Revised draft — final pre-development pass applied (M0 spike,
Computer correlation, evidence sidecar, config, M2 split). Implementation
status is tracked in [`graph-model.md`](../reference/graph-model.md).

## One-liner

LLMHound is a BloodHound OpenGraph collector that remotely maps the attack
surface of LLM and agentic AI infrastructure — MCP servers, A2A agents, LLM
gateways, inference servers, vector stores, model registries, notebooks, and
AI UIs — from a central collection server across your network.

Target positioning: a listing on the SpecterOps OpenGraph community library
page (`bloodhound.specterops.io/opengraph/library`).

## Problem and scope

BloodHound CE (PostgreSQL backend) is the existing attack-path analysis
platform. Compatibility must be validated against an exact CE version,
OpenGraph schema, and required API capabilities; v8+ alone is not sufficient. Corporate infrastructure increasingly runs AI services (Ollama,
vLLM, LiteLLM, Qdrant, MLflow, Jupyter, Open WebUI, MCP servers, A2A agents)
that are invisible to SharpHound/AzureHound and unrepresented in the graph.

LLMHound closes that gap with a **remote, network-based collector** — no
host-local collection, no foothold deployment. It runs on a dedicated scanner
VM as part of an automated ingest pipeline that feeds BloodHound CE. v1 is
an **evidence-first collector** of bounded, anonymous, read-only metadata;
all emitted relationships are non-traversable.

LLMHound **extends an existing BloodHound buildout** rather than building a
parallel host graph: wherever a scanned target can be correlated to an AD
`Computer` already in the graph, observed AI services attach to that node.
Because v1 edges are non-traversable, pathfinding does not traverse into
LLMHound nodes; the value is AI inventory and access evidence joined onto
the Computers that existing AD attack paths already reach.

### In scope (v1)

- Remote, anonymous, read-only enumeration of reachable AI services
- OpenGraph payload emission (structured graph: extension definition schema
  - conforming data payload)
- BloodHound CE API integration: schema registration, payload upload,
  saved-query import
- Target discovery from CIDR ranges and targets files
- Checkpoint/resume for interrupted scans
- Product version/build evidence, per-operation anonymous access outcomes,
  deployment/backend references, MCP/A2A metadata, model provenance, and TLS metadata
- Per-check outcomes with scoped provenance, written to an evidence sidecar
- Correlation of scanned targets to existing AD `Computer` nodes
- A `llmhound.yaml` configuration file for scope, vantage, bounds, opt-ins,
  and correlation settings
- The [collector capability matrix](../reference/collector-capabilities.md)
  defines the allowlisted checks and acceptance contract for every surface
  (ten core surfaces plus the M2c long tail)

### Out of scope (v1)

- Host-local collection (agent configs, instruction files, keychains) —
  rejected; this is a collection-server tool
- Authenticated enumeration (credential plumbing arrives in a later milestone)
- BloodHound Enterprise-only features (environments, privilege zones,
  findings, metrics)
- Change comparisons / an `llmhound diff` command (deferred; see
  [`.future`](.future/future-potential.md)). v1 retains the structured data
  that would make comparison possible.

## Provenance and licensing posture

**LLMHound contains 100% original code.** Reference projects inform behavior
only; no code is copied from any of them:

| Reference                                             | License                    | Use                                                                                                                     |
| ----------------------------------------------------- | -------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| AgentHound (`adithyan-ak/agenthound`)                 | Apache-2.0                 | Behavioral reference: what to enumerate per surface, identity semantics, coverage-outcome honesty. No code.             |
| ShareHound (`p0dalirius/sharehound`)                  | none (all rights reserved) | Architectural reference: targets/worker pool/checkpoint/zip-stream patterns. No code (mandatory).                       |
| Netwrix AIHound (`netwrix/AIHound`)                   | MIT                        | Reference: CE API client surface (login, `PUT /api/v2/extensions`, `POST /api/v2/file-upload`, saved queries). No code. |
| OpenHound (`SpecterOps/OpenHound`) + `openhound-okta` | —                          | Reference: what a complete extension ships (schema, saved searches, descriptions, docs). No code.                       |

Normal public Go dependencies (cobra, `modelcontextprotocol/go-sdk`, etc.)
carry their standard `go.mod` license metadata; nothing in the dependency
graph derives from the reference projects.

## Architecture

Single static Go binary (`llmhound`) deployed on the scanner VM and scheduled
by the existing automated-ingest process.

```
llmhound.yaml (+ flag overrides): scope, vantage, targets/exclude, bounds,
  opt-ins, TLS mode, User-Agent, correlation
targets (CIDR ranges / targets-file, minus exclude)
  → discovery: worker-pool TCP probe of AI-service ports
      + HTTP path fingerprinting (data-driven definitions) → service typing
  → per-service anonymous enumeration modules:
      MCP (tool/resource/prompt metadata) [official go-sdk]
      A2A (agent cards / skills)
      Ollama, vLLM, LiteLLM, Qdrant, MLflow, Jupyter, Open WebUI, LangServe
      M2c: OpenAI-compatible, Ray dashboard, Langflow, Flowise, ChromaDB
  → correlation: target → existing AD Computer, else NetworkEndpoint
  → raw observations → deterministic graph (SHA-256 objectids)
  → emission: OpenGraph payload (JSON; ZIP stream for large scans)
      + evidence sidecar (.evidence.jsonl)
  → BloodHound CE: PUT /api/v2/extensions (register schema),
      POST /api/v2/file-upload (payload), POST /api/v2/saved-queries
  — checkpoint journal throughout, resumable
```

### Pipeline stages

1. **Targets** — parse CIDR ranges and/or a targets file (IPs, FQDNs); dedup;
   remove configured `exclude` entries; optional port expansion.
2. **Discovery** — bounded-concurrency TCP probes against known AI-service
   ports (Ollama 11434, vLLM 8000, MLflow 5000, Jupyter 8888, Qdrant 6333,
   Open WebUI 3000/8080, LiteLLM 4000, MCP/A2A over 80/443/8080 + others);
   HTTP path fingerprinting confirms service type. Ports, paths, and matchers
   are data-driven fingerprint definitions embedded in the binary and
   overridable by file, so adding a product does not require discovery code.
3. **Enumeration** — per-surface allowlisted metadata checks from the
   [capability matrix](../reference/collector-capabilities.md); each check
   records its outcome and reason, separately from the module's coverage
   (`complete` / `partial` / `failed` / `truncated`).
4. **Correlation** — each observed target is matched to an existing AD
   `Computer` or falls back to a `NetworkEndpoint` node (see
   [Computer correlation](#computer-correlation)).
5. **Graph assembly** — observations become nodes/edges with deterministic
   identity.
6. **Emission** — OpenGraph payload and evidence sidecar written to disk
   (payload optionally pushed via the CE API).
7. **Upload** — schema registration, payload upload, saved-query import.

## Repo structure

```
LLMHound/
├── cmd/llmhound/            # CLI entrypoint (cobra)
├── internal/
│   ├── config/              # llmhound.yaml loading, flag overrides, validation
│   ├── targets/             # CIDR/file parsing, dedup, exclude
│   ├── discovery/           # port probes + path fingerprints → service typing
│   │   └── fingerprints/    # embedded, overridable fingerprint definitions
│   ├── collectors/          # one package per AI surface (original clients)
│   ├── correlate/           # target → AD Computer / NetworkEndpoint
│   ├── evidence/            # per-check results, evidence sidecar writer
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

**Extension/source identifier:** `LLMHound` · **source_kind:** `LLMHound`
(for source-owned lifecycle management, subject to adapter validation).

Node and edge kinds use clean logical names such as `OllamaInstance` and
`ProvidesModel`; display names describe the instance, not the collector.
There is no blanket kind prefix. The adapter must verify whether the target
CE schema isolates kinds by extension or shares names globally, then apply
minimal qualification only where required. Document any logical-to-emitted
kind mapping and use it consistently in the schema, payloads, and saved
queries. Ownership and deletion rely on source metadata, not name prefixes.
See the [graph reference](../reference/graph-model.md) for the naming,
identity, evidence-property, and collision contracts.

### Node kinds

| Group              | Kinds                                                                                                                                      |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------ |
| Targets            | existing AD `Computer` (correlated, not emitted); `NetworkEndpoint` (fallback observed target, not authoritative machine identity)          |
| Collection context | `CollectionVantage` (configurable stable scanner/network context)                                                                          |
| MCP                | `MCPServer`, `MCPTool`, `MCPResource`, `MCPPrompt`                                                                                         |
| A2A                | `A2AAgent`, `A2ASkill`                                                                                                                     |
| AI services        | `OllamaInstance`, `VLLMInstance`, `LiteLLMGateway`, `QdrantInstance`, `MLflowServer`, `JupyterServer`, `OpenWebUIInstance`, `LangServeApp` |
| AI services (M2c)  | `OpenAICompatibleEndpoint`, `RayDashboard`, `LangflowInstance`, `FlowiseInstance`, `ChromaInstance`                                        |
| Served models      | `AIModel`                                                                                                                                  |
| Typed resources    | `VectorCollection`, `WorkspaceFile`, `ModelArtifact`, `ArtifactStore`                                                                      |
| Umbrella           | `AIService` (label carried by concrete service nodes; does not own identity)                                                               |

Credential nodes are deferred to the credential milestone.

### Edge kinds

- **Topology:** `ObservedAt` (service → `Computer` or `NetworkEndpoint`)
  records network observation. `RunsOn` is reserved for supported
  runtime placement, never inferred from a responding endpoint alone.
  `ProvidesTool`, `ProvidesResource`, `ProvidesPrompt`,
  `ProvidesModel`, `AdvertisesSkill`, `UsesBackend`,
  and `Contains` record inventory and dependencies.
- **Access evidence:** `UnauthenticatedAccess` (CollectionVantage →
  service) records observed anonymous service access, not merely an open TCP
  port. `PublicAccess` (CollectionVantage → resource) records an
  observed anonymous read; no denied-control request is required. Neither
  implies access from every network or by every principal.

**All v1 edges are non-traversable**, including access evidence. Access
observations are scoped to the exact operation, target, vantage, and time;
a successful metadata check does not establish service-wide access.

### Identity

Deterministic SHA-256 `objectid` values include an explicit tenant/deployment
scope and kind-specific identity fields. Service identity includes the
concrete kind and canonical endpoint scheme, host, effective port, and base
path. Canonicalization must normalize equivalent endpoint spellings without
collapsing distinct virtual hosts, schemes, ports, base paths, or service
kinds. DNS resolution, shared IPs, and redirects do not prove identity.
`AIService` is an umbrella label, not an identity owner.

Resources use the owning service identity plus a stable resource key
(collection name, model name, workspace path, or registered model name and
artifact version). Display names, timestamps, observed software versions,
and mutable descriptions never define identity. `NetworkEndpoint` identity
represents a scoped observed network target, not a physical or virtual
machine. CollectionVantage identity uses a configured stable key within the
same scope, rather than a per-scan ID; materially different network contexts
must be distinguishable. Run IDs and observation times remain provenance.

### Computer correlation

LLMHound dedups observed targets against the AD `Computer` nodes already in
BloodHound instead of creating parallel host nodes. Full contract in the
[graph reference](../reference/graph-model.md#computer-correlation).

- **Sources, in precedence order:** (1) an operator-supplied mapping file
  (target → Computer objectid/SID); (2) an FQDN inside a configured AD
  domain-suffix list, matched to the Computer by property at ingest, only if
  the M0 spike confirms CE supports property-matched edge endpoints;
  (3) an optional pre-scan lookup through the CE API (M3) that resolves to
  exact objectids. IP-only targets correlate only via the mapping file or an
  explicit reverse-DNS opt-in.
- **Result:** a correlated target gets `ObservedAt` (service → existing
  `Computer`) carrying `match_method`, `match_value`, and `confidence`. An
  uncorrelated or ambiguous target (several candidate Computers) falls back to
  a `NetworkEndpoint` node; ambiguous candidates are recorded in evidence.
- **Not an identity merge.** Correlation is an edge to an existing node.
  LLMHound service objectids never depend on it, native BloodHound IDs are
  never overwritten, and source-scoped cleanup never touches `Computer` nodes.
  A later scan that newly correlates a target attaches to the Computer.

### Metadata and evidence contract

The [collector capability matrix](../reference/collector-capabilities.md)
is the per-surface contract: checks are anonymous, bounded, read-only, and
restricted to allowlisted metadata operations. Endpoint availability varies
by product, version, configuration, and deployment; listing a check does not
promise that an endpoint exists or permits anonymous access. Sensitive existing
resource content requires explicit opt-in, bounded reads, and redaction.

- **Product version/build:** each collector must attempt applicable allowlisted
  version checks and record their outcomes, including why a check was skipped.
  Preserve product/vendor, reported version/build, source field or header,
  collection time, and whether evidence is advertised, observed, or inferred.
  Unknown versions remain unknown. Product versions are distinct from protocol,
  API, and model versions; none substitutes for another.
- **Per-operation access:** record the exact metadata operation and observed
  result, not a service-wide access assumption. Advertised authentication
  requirements are separate from observed anonymous access.
- **Deployment/backend references:** preserve advertised or observed deployment
  identifiers and backend references with source and time; redact credentials.
  References do not establish reachability or runtime placement. FQDN, shared
  IPs, proxies, and DNS changes are insufficient for automatic identity merges.
  Any follow-up to backend URLs, artifact locations, or agent links must
  independently satisfy authorized target scope and the allowlisted bounds.
- **MCP/A2A metadata:** collect available server/agent identity, capabilities,
  protocol versions, tool schemas, resource descriptors/templates, prompt
  descriptors, agent-card skills/interfaces, and advertised security metadata.
  Descriptors are metadata, not permission to read their referenced content.
- **Model provenance:** retain advertised model identifiers, versions, digests,
  ownership/source references, and registry/artifact relationships where exposed
  by allowlisted metadata checks. Record provenance and distinguish reported
  claims from independently observed facts; missing provenance stays unknown.
- **TLS metadata:** record available certificate identity, issuer, validity,
  fingerprints, negotiated TLS details, and verification result with source/time.
  A verification failure does not authorize bypass or application-level follow-up;
  only explicit insecure mode permits unverified collection, marked as such.
  Metadata unavailable after a failed handshake remains unknown.

Every planned check has an outcome and reason: `success` (expected metadata
operation completed), `denied` (explicit access denial), `unsupported`
(positive evidence the operation is not supported), `failed` (transport,
protocol, parsing, or unresolved response failure), or `skipped` (not attempted,
with a policy, applicability, or prerequisite reason). HTTP 404 alone is
ambiguous, not proof of `unsupported`; preserve its evidence and report the
unresolved failure honestly. Per-check outcomes are separate from existing
surface coverage values, and `success` does not imply exhaustive coverage.

### Observation lifecycle and payload safety

Carry scan/run identity, observation time, collection vantage, evidence
source, and per-surface coverage (`complete`, `partial`, `failed`,
`truncated`). Preserve first/last-seen and freshness meaning across rescans
without putting timestamps in object IDs. A failed, partial, or truncated
scan is not evidence of removal or revocation. Any later reconciliation
must consider scope, vantage, coverage, and age; absence alone must not
silently delete evidence. Resume must retain the original observation
provenance rather than refreshing stale evidence as newly observed.

Change comparisons are deferred. v1 retains enough structured evidence
(scope, vantage, check policy, bounds, outcomes, source/time) for a later
comparison tool to report only like-for-like changes. Denied, failed, or
incomplete collection must never be presentable as removal or revocation.

### Outputs and configuration

- **OpenGraph payload** — `llmhound-<ts>.json` (or `.zip`): nodes and edges
  with flat, queryable properties that reference evidence by stable ID.
- **Evidence sidecar** — `llmhound-<ts>.evidence.jsonl`: one record per
  check result, fingerprint, TLS observation, redirect, and correlation
  decision. It holds the bounded structured evidence that graph properties
  cannot represent. The same redaction, size-limit, retention, and access
  rules apply as for payloads and journals.
- **`llmhound.yaml`** — deployment scope, vantage key, targets and `exclude`,
  concurrency/rate/timeout/size bounds, sensitive-content opt-ins, TLS mode,
  User-Agent, and `correlation` (mapping file, AD domain suffixes,
  reverse-DNS opt-in, CE lookup). Flags override file values; the effective
  policy is recorded with each scan. Invalid or missing required values
  (scope, vantage) fail before any network activity.

Retain only necessary bounded evidence, preferring structured metadata and
redacted excerpts over raw responses. Exclude secrets and URL credentials;
apply explicit opt-in and size limits to sensitive content such as prompts,
configuration, or workspace contents. Payloads and checkpoint journals need
restricted access and documented retention/deletion controls. Sanitization
must cover logs as well as emitted graph properties.

## Scanning behavior (v1: anonymous, read-only)

- **No credentials used.** Enumerate, fingerprint, record only allowlisted
  metadata operations. Sensitive existing content is opt-in, not a default check.
- **Bounded:** configurable concurrency, per-host rate limiting, connect and
  response timeouts, page/count/byte limits, and redirect limits.
- **TLS verification on by default**; never retry unverified after failure
  unless `--insecure` was explicitly selected; retain that choice in evidence.
- **Authorized redirects only:** recheck target authorization on every hop;
  advertised links and redirects cannot expand collection scope.
- **Per-check outcomes:** every matrix check records an outcome and reason,
  including required version attempts and any prerequisite or policy skips.
- **Identifiable:** a fixed, configurable `User-Agent`
  (`LLMHound/<version> (+contact)`) so defenders can attribute scan traffic.
- **Reviewable before running:** `llmhound plan` prints the targets × checks a
  scan would perform, without sending traffic to targets.
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

1. `llmhound scan --config llmhound.yaml` (or `--targets-file`/`--cidr`
   overrides) → `llmhound-<timestamp>.json` (+ optional `.zip`) and
   `llmhound-<timestamp>.evidence.jsonl`
2. `llmhound upload --server https://bloodhound.corp --token-file ...`
   registers the extension schema, uploads the payload, imports saved
   queries
3. Scanner VM cron/systemd drives both; your existing automated ingest can
   also pick up the emitted files directly (UI upload or API)

### BloodHound adapter validation gate

Before declaring a CE release supported, validate its exact version and
OpenGraph schema/capabilities against fixtures: extension registration,
accepted node labels/properties, edge direction and non-traversability,
deterministic identity/upsert behavior, payload upload and processing,
saved-query import/execution, property-matched edges to existing `Computer`
nodes, and source-scoped cleanup. Record the tested
version/schema combination. Detect unsupported or unknown capabilities and
fail upload with an actionable diagnostic rather than silently changing
semantics; local payload emission remains available. Published schema
conformance alone does not establish server compatibility.

## Testing strategy

- **Unit:** per-collector tests against `httptest` fake services
- **Config:** required-field validation, flag overrides, `exclude` handling,
  and recording of the effective policy
- **Emission:** golden-file tests for OpenGraph payload and evidence sidecar
  output; schema conformance validated against the published OpenGraph JSON
  schemas
- **Correlation:** exact mapping-file match, AD-suffix FQDN match, suffix
  mismatch, ambiguous candidates → `NetworkEndpoint`, IP-only without opt-in,
  correlation appearing on a rescan, service IDs unchanged by correlation,
  and cleanup never touching `Computer` nodes
- **Identity:** canonical endpoint equivalence; separation across tenant/
  deployment, concrete kind, scheme, virtual host, port, and base path;
  stable resource ownership and vantage IDs; no identity change from mutable
  metadata; no DNS/IP/FQDN-driven identity merges (correlation edges only)
- **Semantics:** correct vantage → service/resource access evidence; anonymous
  reads without denied controls; no access claim from a TCP probe alone;
  ObservedAt does not imply RunsOn; every v1 edge remains non-traversable;
  no automatic identity merge or advertised-dependency access claim
- **Lifecycle:** repeated scans/upserts, first/last-seen and freshness,
  coverage-aware absence, failure/truncation without deletion, vantage
  changes, and kill/resume determinism with original evidence timestamps
- **Matrix contract:** fixtures for every allowlisted check across every
  surface, covering available, denied, demonstrably unsupported, ambiguous
  404, malformed, transport-failed, and skipped cases as applicable. Assert
  outcome plus reason separately from surface coverage, and do not assume
  unavailable endpoints work. Record version attempts or explicit skip reasons;
  test unknown versions and separation of product/build, protocol, API, and
  model versions. Check MCP/A2A metadata, model provenance, deployment/backend
  references, and per-operation access without broadening access claims.
  Surfaces are added per milestone (M2a, M2b, M2c).
- **Collection safety:** request recording proves only allowlisted, bounded,
  read-only metadata checks run by default; enforce time/page/count/byte limits.
  Test sensitive existing content disabled by default, explicit opt-in, and
  redaction across payloads/journals/logs. Test each redirect's authorization,
  advertised URLs not fetched outside authorized scope, and credential removal.
- **TLS:** valid, expired, untrusted, hostname-mismatched, and failed-handshake
  fixtures; retain available metadata and honest unknowns, no automatic insecure
  retry or application collection after verification failure, and explicit
  insecure-mode provenance.
- **Adapter:** fixtures for supported and unsupported version/schema/API
  capabilities, actionable rejection, upload-processing errors, and saved
  query compatibility
- **Integration (optional per CI run, required for release support):**
  docker-compose CE + PostgreSQL pinned to the tested version; end-to-end
  registration/upload and Cypher verification of nodes, edge direction,
  non-traversability, Computer-correlated edges, rescans/upserts, saved
  queries, and source-scoped cleanup

## Milestones

0. **M0 — CE compatibility spike:** docker-compose CE + PostgreSQL at a pinned
   version; register a toy extension and upload a toy payload. Answer the
   questions in [`ce-compatibility.md`](../reference/ce-compatibility.md):
   kind namespacing and prefix-vs-clean names, multi-label `AIService`,
   allowed property types, non-traversable edge declaration, `source_kind`
   cleanup, and property-matched edge endpoints against `Computer`. M1's
   schema is written from these answers.
1. **M1 — Skeleton + graph + emitter:** CLI, `llmhound.yaml` loader,
   targets, graph model, OpenGraph emission plus evidence sidecar, schema,
   `LICENSE` (Apache-2.0), golden tests. Readiness requires scoped/canonical
   identity fixtures, vantage/access direction and all-non-traversable
   semantics tests, correlation fixtures (mapping file and AD-suffix),
   lifecycle/provenance field contracts, and the M0-recorded capabilities.
2. **M2a — Vertical slice:** discovery with data-driven fingerprints, the
   checkpoint journal interface (collectors write through it), `llmhound
   plan`, and MCP, Ollama, Jupyter collectors end-to-end to payload.
3. **M2b — Remaining core surfaces:** A2A, vLLM, LiteLLM, Qdrant, MLflow,
   Open WebUI, LangServe.
4. **M2c — Long tail:** generic `OpenAICompatibleEndpoint` (llama.cpp, TGI,
   LM Studio, LocalAI, SGLang; used whenever a specific product cannot be
   proven) plus Ray dashboard, Langflow, Flowise, and ChromaDB.

   Every M2 surface is accepted under the
   [capability matrix](../reference/collector-capabilities.md): per-check
   fixtures and outcomes/reasons, required product version attempts with
   honest unknowns, separate surface coverage, deployment/backend and model
   provenance, MCP/A2A metadata, per-operation access evidence, TLS metadata
   with verification enforcement, authorized redirects, and bounded
   metadata-only defaults with sensitive-content opt-in. The matrix, collector
   behavior, and tests must agree; unavailable or denied endpoints are
   recorded honestly, not treated as promised collection successes.
5. **M3 — Resume + upload:** resume, CE API client, saved queries,
   CE-API Computer lookup for correlation, end-to-end against a CE instance.
   Readiness requires lifecycle and resume tests, unsupported-capability
   rejection, and the adapter validation gate against a recorded exact CE
   version/schema combination, including non-traversability, Computer
   correlation, repeated uploads, and cleanup.
6. **M4 — Credentials (future):** authenticated enumeration and access
   evidence
7. **M5 — Library listing (future):** README polish, node/edge description
   docs, submission PR to the BloodHound docs repo
