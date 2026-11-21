# LLMHound — Design

**Revised:** 2026-11-21 · **Reading order:** 2 of 8 (see [docs index](README.md))

Architecture, scope, and behavior. This is the *what and how*; the *why* is in the
[executive summary](00-executive-summary.md), the graph contract is in the
[graph model](02-graph-model.md), per-surface checks are in the
[capability matrix](03-collector-capabilities.md), and milestones and status are in
the [roadmap](06-roadmap.md). Where this document describes something not yet
built, the [implementation status](02-graph-model.md#implementation-status) says so.

## Purpose

LLMHound is a BloodHound OpenGraph collector that remotely maps LLM and
agentic AI infrastructure (MCP servers, A2A agents, LLM gateways, inference
servers, vector stores, model registries, notebooks, AI UIs) and **enriches an
existing corporate attack-path graph**. SharpHound runs first, then
AzureHound and other collectors; LLMHound maps on top of the infrastructure
those already identified.

The question the program answers is: **from this asset, what is the shortest
attack path to tier 0?** LLMHound contributes context that improves that
answer. Its acceptance questions:

1. Are there hosts running AI/MCP services on an attack path?
2. What is the shortest path from a given asset to compromise an AI host?
3. Which AI hosts are within one or two hops of tier 0?
4. Which AI hosts are anonymously reachable and expose an execution-capable
   surface?
5. Which AI hosts are reachable from owned or low-privilege principals?
6. Which gateways or UIs depend on backends on other hosts?
7. Which AI services are not yet attributed to a known asset?

The [saved queries](04-saved-queries.md) implement these, and they
decide which properties must be flat and queryable.

## Scope

### In scope (v1)

- Remote, anonymous, read-only enumeration of reachable AI services
- Attachment to existing BloodHound nodes (any kind) from an externally
  supplied asset mapping; a `NetworkEndpoint` fallback for unmapped targets
- Maximum useful metadata within that policy: identity and version, auth
  posture, execution surface, dependencies, inventory, TLS (the
  [min-max principle](02-graph-model.md#property-contract))
- Content tier collected by default when one anonymous allowlisted read returns
  it (system prompts, configuration, file and flow bodies, bounded samples),
  plus precision-only detection of exposed secrets, recorded as a boolean with
  no value stored ([Content and secrets](02-graph-model.md#content-and-secrets))
- OpenGraph payload and an evidence sidecar per scan
- Opt-in, rule-gated traversable edges for cases that clear the
  [path-qualification bar](02-graph-model.md#path-qualification-traversable-edges)
- Checkpoint/resume, CE API upload, saved-query import

### Out of scope (v1)

- Host-local collection (agent configs, instruction files, keychains)
- Authenticated enumeration (M4), including any use or validation of
  credentials found in content; credential guessing or default-credential tests
- Target attribution, reverse DNS or FQDN guessing, CE-side lookups, stale-data
  reconciliation and cleanup — owned by the separate normalization program
- Active exploit validation, tool invocation, inference requests
  (see [future ideas](future-ideas.md))
- BloodHound Enterprise-only features
- Change comparisons / `llmhound diff` (deferred)

## Provenance and licensing posture

**LLMHound contains 100% original code.** Reference projects inform behavior
only; no code is copied from any of them.

| Reference | License | Use |
|---|---|---|
| AgentHound (`adithyan-ak/agenthound`) | Apache-2.0 | Behavioral reference: what to enumerate per surface, identity semantics, coverage honesty. No code |
| ShareHound (`p0dalirius/sharehound`) | none (all rights reserved) | Architectural reference: targets/worker pool/checkpoint/zip-stream patterns. No code (mandatory) |
| Netwrix AIHound (`netwrix/AIHound`) | MIT | Reference: CE API client surface. No code |
| OpenHound (`SpecterOps/OpenHound`) + `openhound-okta` | — | Reference: what a complete extension ships. No code |

Normal public Go dependencies (cobra, `modelcontextprotocol/go-sdk`) carry
their own `go.mod` license metadata; nothing in the dependency graph derives
from the reference projects. LLMHound is Apache-2.0.

## Architecture

Single static Go binary (`llmhound`) on a dedicated scanner VM, scheduled by the
existing ingest process, run after SharpHound/AzureHound collection.

```
llmhound.yaml (+ flag overrides): scope, vantage_key, targets/exclude, bounds,
  content/secrets settings, TLS mode, User-Agent, mapping_file,
  assumed_reach_principals, rules
targets (CIDR ranges / targets-file, minus exclude)
  → discovery: worker-pool TCP probe of AI-service ports
      + HTTP path fingerprinting (data-driven definitions) → service typing
  → per-service anonymous enumeration modules (MCP via official go-sdk, A2A,
      Ollama, vLLM, LiteLLM, Qdrant, MLflow, Jupyter, Open WebUI, LangServe;
      M2c: OpenAI-compatible, Ray, Langflow, Flowise, ChromaDB)
  → attachment: mapping file → existing node objectid, else NetworkEndpoint
  → content tier + secret detection (bounded; secret values discarded)
  → classification: auth posture, execution surface, dependencies
  → deterministic graph (SHA-256 objectids) + optional path-qualification rules
  → emission: OpenGraph payload (JSON; ZIP stream for large scans)
      + evidence sidecar (.evidence.jsonl) + restricted content file (.content.jsonl)
  → BloodHound CE: PUT /api/v2/extensions, job-based file upload
      (/api/v2/file-upload/*), POST /api/v2/saved-queries/import
  — checkpoint journal throughout, resumable
```

### Pipeline stages

1. **Targets** — parse CIDR ranges and/or a targets file (IPs, FQDNs); dedup;
   remove `exclude` entries; optional port expansion.
2. **Discovery** — bounded-concurrency TCP probes against known AI-service
   ports (Ollama 11434, vLLM 8000, MLflow 5000, Jupyter 8888, Qdrant 6333,
   Open WebUI 3000/8080, LiteLLM 4000, MCP/A2A over 80/443/8080 + others), then
   HTTP path fingerprinting. Ports, paths, and matchers are data-driven
   definitions embedded in the binary and overridable by file.
3. **Enumeration** — per-surface allowlisted checks from the
   [capability matrix](03-collector-capabilities.md); each check
   records outcome and reason, separately from surface coverage.
4. **Content and secrets** — where one allowlisted anonymous read returns
   existing content, read it within byte/item bounds into the restricted
   content file; run the high-precision secret detectors and keep only a
   presence flag and type ([rules](02-graph-model.md#content-and-secrets)).
5. **Attachment** — mapping-file lookup, per the
   [attachment contract](02-graph-model.md#attachment-to-existing-nodes).
6. **Graph assembly** — observations become nodes/edges with deterministic
   identity and the flat property contract, including auth posture and
   execution-surface classification.
7. **Rules (optional)** — enabled path-qualification rules may emit traversable
   edges; with none enabled, every edge is non-traversable.
8. **Emission and upload** — payload, evidence sidecar, and content file
   written to disk; payload optionally registered and uploaded via the CE API.

## Repo structure

```
LLMHound/
├── README.md                 # human overview
├── AGENTS.md                 # agent operating manual (CLAUDE.md imports it)
├── LICENSE                   # Apache-2.0
├── llmhound.example.yaml     # annotated example configuration
├── cmd/llmhound/             # CLI entrypoint (cobra): targets, plan, scan, upload (stub)
├── internal/
│   ├── config/               # llmhound.yaml loading, flag overrides, validation
│   ├── targets/              # CIDR/file parsing, dedup, exclude
│   ├── discovery/            # data-driven port probes + path fingerprints → service typing
│   ├── transport/            # shared bounded, TLS-aware HTTP client
│   ├── collectors/           # one package per surface: jupyter, mcp, ollama, a2a, vllm, qdrant (more in M2b/M2c)
│   ├── content/              # bounded content-tier records, redaction hook, 0600 lazy writer
│   ├── secrets/              # parse/checksum-verified secret detectors over content bodies
│   ├── correlate/            # asset mapping → existing native node, else NetworkEndpoint
│   ├── graph/                # identity, kinds, observations, edges, access summary
│   ├── evidence/             # per-check results, evidence sidecar records and writer
│   ├── emitter/              # OpenGraph base + linking payloads, evidence sidecar
│   ├── checkpoint/           # scan journal + deterministic replay
│   ├── savedsearch/          # Cypher query validation and saved-search generator helpers
│   └── scanner/              # orchestration: discovery → collectors → journal → emission
├── extension/
│   ├── schema.json           # OpenGraph extension definition (LLMHound_* kinds)
│   └── saved_searches/       # generated CE saved queries (P1, P2, P4, P6)
├── tools/
│   └── gensearches/          # generates extension/saved_searches/ from internal/graph kinds
├── lab/                      # pinned BloodHound CE lab + M0/D2 compatibility checks
├── docs/                     # numbered core docs + guides/, collectors/, internals/
└── legacy/                   # retired docs and code, kept for history (not built)
```

Planned, not yet present: `internal/rules` and `extension/rules`
(path-qualification, M2d), and `internal/bloodhound` (CE API client, M3).

## Graph model

The graph model is specified in
[`graph-model.md`](02-graph-model.md): node and edge kinds, identity,
attachment, the flat property contract, coverage, content and secrets, path
qualification, and acceptance checks. Per-surface checks and outcomes are in
[`collector-capabilities.md`](03-collector-capabilities.md). Key
design points:

- Source identifier and `source_kind` are `LLMHound`; kinds use clean logical
  names in code and docs, mapped centrally to `LLMHound_<Kind>` in
  `internal/graph/kinds.go` (M0 Q1).
- Services attach to **existing** nodes by objectid from the mapping file. No
  FQDN guessing, no identity merge, no native nodes emitted or modified.
- Anonymous access is recorded as flat properties, not edges.
- Nothing is traversable unless an opt-in rule clears the qualification bar.

## Outputs and configuration

- **OpenGraph payload** — `<prefix>.json` (or `<prefix>-base.json` +
  `<prefix>-linking.json` when native mapping correlation applies; ZIP streaming
  planned): nodes and edges with flat, queryable properties referencing evidence
  by stable ID.
- **Evidence sidecar** — `<prefix>.evidence.jsonl`: one record per check
  result, fingerprint, TLS observation, redirect, and attachment decision.
  Shareable: no content bodies or raw secrets.
- **Content file** — `<prefix>.content.jsonl` (mode 0600): bounded content
  bodies with secret spans replaced by `[secret:<type>]`. Not shipped through
  the BloodHound ingest pipeline.
- **Checkpoint journal** — `<prefix>.journal.jsonl`: append-only scan journal
  used for deterministic replay and planned resume (M3).
- **`llmhound.yaml`** — built keys: deployment `scope`, `vantage_key`,
  `targets`/`cidrs`/`targets_files` and `exclude`/`exclude_files`, `bounds`
  (concurrency/rate/timeout/size/page/item/redirect limits), `content` settings
  (global and per-surface enable, byte/item/sample caps), `secrets.detectors`
  enables, `insecure` TLS mode, `user_agent`, and `correlation.mapping_file`.
  Planned for M2d: `assumed_reach_principals` and enabled `rules`. Flags
  override file values; the effective policy is recorded with each scan. Missing
  required values (scope, vantage key) fail before any network activity.

Retain bounded evidence, preferring structured metadata and redacted excerpts
over raw responses. Payloads and journals need restricted access and documented
retention/deletion controls. Sanitization covers logs as well as graph
properties.

## Scanning behavior (v1: anonymous, read-only)

- **No credentials sent, guessed, or tested.** Enumerate, fingerprint, and read
  only through allowlisted anonymous operations. Existing content is read by
  default when one such read returns it, within byte/item bounds; exposed
  secrets are flagged as a boolean by high-precision detectors only, the value
  discarded, and never used or validated.
- **Bounded:** concurrency, per-host rate limits, connect/response timeouts,
  page/count/byte limits, redirect limits.
- **TLS verification on by default;** never retry unverified unless `--insecure`
  was explicitly selected, and record that choice.
- **Authorized redirects only:** recheck target authorization on every hop;
  advertised links cannot expand scope.
- **Per-check outcomes** for every matrix check, including version attempts and
  policy skips.
- **Identifiable:** configurable `LLMHound/<version> (+contact)` User-Agent.
- **Reviewable:** `llmhound plan` prints targets × checks without sending
  traffic.
- **Honest coverage:** `complete`/`partial`/`failed`/`truncated`; partial scans
  stay useful and never overstate coverage.
- **Payload before exit:** an ingest-valid payload is always written, even on
  partial failure. Unreachable targets and module errors degrade only that
  surface.

## Ingest pipeline

1. SharpHound/AzureHound collection and the normalizer's asset mapping run first.
2. `llmhound scan --config llmhound.yaml` → payload + sidecar.
3. `llmhound upload --server … --token-file …` (M3) registers the schema, then
   uploads in **two steps** (M0 Q5): the LLMHound-owned subgraph with
   `source_kind`, then a linking payload to existing native nodes **without**
   it, after a read-only existence pre-flight (missing endpoints would create
   stub nodes). It then imports saved queries. Or the existing ingest picks up
   the emitted files.

### BloodHound adapter validation gate

Before declaring a CE release supported, validate its exact version and
OpenGraph schema/capabilities against fixtures: extension registration,
accepted labels and property types (including arrays), edge direction,
non-traversability and rule-enabled traversability in pathfinding, attachment
to SharpHound/AzureHound nodes by objectid, missing-node behavior, repeated
upload/upsert, saved-query import and execution, and provenance tagging.
Record the tested version/schema combination. Unsupported or unknown
capabilities fail upload with an actionable diagnostic; local emission always
remains available.

## Testing strategy

- **Unit:** per-collector tests against `httptest` fake services.
- **Config:** required-field validation, overrides, `exclude`, effective policy.
- **Emission:** golden-file tests for payload and sidecar; schema conformance.
- **Attachment:** mapped (any node kind), unmapped, multi-candidate mapping,
  service IDs unchanged by mapping, no native nodes emitted.
- **Identity, semantics, property contract, versions, content and secrets,
  and path qualification:** the checks in
  [graph model → acceptance](02-graph-model.md#implementation-acceptance-checks).
- **Matrix contract:** fixtures for every allowlisted check across every
  surface (available, denied, demonstrably unsupported, ambiguous 404,
  malformed, transport-failed, skipped), asserting outcome and reason apart
  from coverage; version attempts and unknown-version handling; auth and
  execution-surface classification with correct basis. Surfaces are added per
  milestone.
- **Collection safety:** request recording proves only allowlisted, bounded,
  read-only checks run; limits enforced; content tier bounded and disableable;
  secret detectors proven against zero-false-positive corpora and secret values
  absent everywhere; no credential ever sent; per-hop redirect authorization.
- **TLS:** valid, expired, untrusted, mismatched, and failed-handshake
  fixtures; no automatic insecure retry; explicit override provenance.
- **Adapter:** supported/unsupported version/schema fixtures, actionable
  rejection, upload-processing errors, saved-query compatibility.
- **Integration (optional per CI run, required for release support):**
  docker-compose CE + PostgreSQL pinned to the tested version with SharpHound
  and AzureHound sample data; end-to-end registration/upload and Cypher
  verification of attachment, non-traversability, the headline queries, and
  rescans.

## Milestones

Milestones, status, and the development backlog live in the [roadmap](06-roadmap.md).
