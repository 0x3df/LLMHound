# LLMHound

**Map the attack surface of AI infrastructure into BloodHound with OpenGraph.**

LLMHound is a BloodHound [OpenGraph](https://bloodhound.specterops.io/opengraph/overview)
collector for LLM and agentic AI infrastructure: MCP servers, A2A agents, LLM
gateways, inference servers, vector stores, model registries, notebooks, and
AI UIs. The planned collector runs on a central collection server, scans your
network remotely, and extends your existing BloodHound graph: AI services attach to the Active
Directory `Computer` nodes you already have, so you can see which machines on
your existing attack paths are running AI services and what those services
expose anonymously.

v1 edges are **non-traversable**. BloodHound pathfinding does not traverse
into LLMHound nodes. v1 adds inventory and scoped access evidence joined onto
AD Computers; it does not claim new attack transitions.

```
targets → network scan → OpenGraph payload + evidence sidecar → AI services on your AD Computers
```

> [!NOTE]
> **Status: M2a vertical slice wired into the CLI.** Offline `targets` and
> `plan`, plus `scan` for Jupyter, MCP, and Ollama, write OpenGraph payloads,
> evidence sidecars, and checkpoint journals through the shared discovery,
> collector, checkpoint, graph, and emitter contracts. Computer correlation via
> mapping file / AD-suffix matching is exercised in scan integration tests;
> CE API lookup, resume, and `upload` remain M3. Sensitive content defaults stay
> off (metadata-only / read-only). See [configuration](docs/reference/configuration.md),
> [collector capabilities](docs/reference/collector-capabilities.md), and the
> [M2a integration note](docs/reference/m2a-integration.md) for live vs unit
> coverage. The [design](docs/plans/2026-09-29-llmhound-design.md) covers the
> full roadmap; the [M0 lab](lab/README.md) records CE spike results.

## Contents

- [What it finds](#what-it-finds)
- [How it works](#how-it-works)
- [BloodHound integration](#bloodhound-integration)
- [Quick start](#quick-start)
- [Collection workflow](#collection-workflow)
- [Operational model](#operational-model)
- [Responsible use](#responsible-use)
- [Roadmap](#roadmap)
- [Licensing](#licensing)

## What it finds

**M2a surfaces (Jupyter, MCP, Ollama) are implemented in `scan`.** Remaining
rows are roadmap. v1 collection is **anonymous, bounded, and read-only**:
LLMHound sends no credentials to scanned services and checks only allowlisted
metadata operations. Sensitive existing resource content is collected only with
explicit opt-in, size limits, and redaction. The
[collector capability matrix](docs/reference/collector-capabilities.md)
defines each surface's checks and evidence contract; endpoint availability
varies by product, version, and deployment, so collection is not guaranteed.

| Surface        | What v1 collects                                                                                                  |
| -------------- | ----------------------------------------------------------------------------------------------------------------- |
| **MCP**        | Server identity/capabilities, protocol metadata, tool schemas, resource descriptors/templates, prompt descriptors |
| **A2A**        | Agent-card identity, skills, capabilities, interfaces, and advertised authentication requirements                 |
| **Ollama**     | Served-model metadata, digests, and advertised model provenance                                                   |
| **vLLM**       | Server fingerprint, served-model metadata, and advertised deployment details                                      |
| **LiteLLM**    | Gateway fingerprint, model catalog, and redacted deployment/backend references                                    |
| **Qdrant**     | Vector-collection metadata, point counts, and schema context                                                      |
| **MLflow**     | Experiment and registered-model metadata, model provenance, and artifact-store references                         |
| **Jupyter**    | Authentication posture, session metadata, and workspace listings (not file contents)                              |
| **Open WebUI** | Instance fingerprint and advertised backend references                                                            |
| **LangServe**  | App fingerprint, advertised runnable inventory, and input/output schema metadata                                  |

Planned after the core ten (M2c): a generic **OpenAI-compatible** endpoint kind
for servers such as llama.cpp, TGI, LM Studio, LocalAI, and SGLang when the
product cannot be proven, plus **Ray dashboard**, **Langflow**, **Flowise**, and
**ChromaDB**.

Across all surfaces, the plan includes product version/build evidence,
per-operation anonymous-access outcomes, deployment/backend references, TLS
metadata. Every collector must attempt
applicable allowlisted version checks and report unknown honestly; product
versions stay distinct from protocol, API, and model versions. Advertised
references and model provenance retain their sources, not assumed verification.

Collection is network-only; host-local scanning is out of scope. The CLI
reads only operator-supplied configuration, target/exclusion input files, and
optional discovery fingerprint overrides — not target-service configs,
environment variables, or keychains.

## How it works

**M2a pipeline (targets → plan/scan → payload):** wired for Jupyter, MCP, and
Ollama. Resume and CE upload remain later milestones.

1. **Targets.** CIDR ranges and/or a targets file of IPs and FQDNs,
   deduplicated (`llmhound targets` stays offline).
2. **Discovery.** Data-driven HTTP path fingerprints (`internal/discovery`)
   type services on known default ports; definitions are embedded and
   overridable via `--discovery-file`. Scan probes each configured surface
   once and collects only on a match; unreachable or unmatched surfaces are
   journaled as failed coverage, and a cancelled scan stops instead of
   recording fabricated coverage.
3. **Enumeration.** A read-only collector per surface. Each one records how
   far it got as a coverage outcome: `complete`, `partial`, `failed`, or
   `truncated` (stopped at a configured page or size bound). Separately, each
   check records `success`, `denied`, `unsupported`, `failed`, or `skipped`,
   with a reason. `unsupported` requires evidence; HTTP 404 alone is ambiguous.
4. **Correlation.** Each target is matched to an existing AD `Computer`
   (mapping file or configured AD domain suffixes; CE API lookup is M3). An
   unmatched target becomes a `NetworkEndpoint` node.
5. **Emission.** One OpenGraph payload plus an `.evidence.jsonl` sidecar and
   a checkpoint journal. Deterministic IDs include tenant/deployment scope;
   service IDs include concrete kind and canonical scheme/host/port/base path.
6. **Upload.** Register the extension schema, upload the payload, and import
   saved queries through the BloodHound CE API (M3). Or skip this step and let
   your existing ingest pipeline pick up the file.

## BloodHound integration

Targets **BloodHound CE with PostgreSQL**. Support requires validation of the
exact CE version, OpenGraph schema, and API capabilities; a version number
alone is not a compatibility guarantee.

- **Extension schema.** `extension/schema.json` uses `LLMHound_`-prefixed
  kinds such as `LLMHound_OllamaInstance` and `LLMHound_ProvidesModel`, as
  required by the validated CE release (see the
  [graph model](docs/reference/graph-model.md#naming-contract)).
  All v1 edges are non-traversable.
- **Attached to your AD Computers.** `ObservedAt` links a service to the
  existing AD `Computer` it was correlated to, or to a fallback
  `NetworkEndpoint`. Correlation is an edge, not an identity merge. LLMHound
  never overwrites native BloodHound IDs, and cleanup never touches
  `Computer` nodes. `RunsOn` is reserved for proven runtime placement; a
  matching FQDN is not enough for either an identity merge or runtime placement.
- **Scoped access evidence.** A configurable, stable
  `CollectionVantage` identifies scanner/network context.
  `UnauthenticatedAccess` links vantage → service;
  `PublicAccess` links vantage → resource for an observed anonymous
  read, without requiring a denied control.
- **Clean removal.** All data is tagged with `source_kind` `LLMHound`, so you
  can bulk-delete it from CE database management (subject to M0/M3
  validation).
- **Starter queries.** Saved Cypher searches in
  `extension/saved_searches/`, in SpecterOps Query Library format; see the
  [planned list](docs/reference/saved-queries.md).

Access evidence is scoped to the operation, target, collection vantage, and
observation time; one successful check does not establish service-wide access.

The full node and edge model, including identity rules and coverage
properties, is in [`docs/reference/graph-model.md`](docs/reference/graph-model.md).

## Quick start

Requires Go 1.27 or newer (tested with 1.27.1):

```bash
CGO_ENABLED=0 go build -o llmhound ./cmd/llmhound
./llmhound --help
./llmhound targets --config llmhound.example.yaml
# 192.0.2.2
# 192.0.2.3
# ai.example.test

# Offline targets × checks inventory (no traffic)
./llmhound plan --config llmhound.example.yaml

# Scan prepared targets (writes journal + OpenGraph + evidence sidecar)
./llmhound scan --config llmhound.example.yaml --output-dir ./out --prefix lab

go test -race ./...
go vet ./...
```

`targets` validates required deployment scope/vantage and bounds, expands
bounded IP/FQDN/CIDR inputs, deduplicates, removes exact-name/IP/CIDR exclusions,
and prints sorted targets without DNS or target traffic. `plan` prints the
allowlisted check inventory without contacting targets. `scan` discovers and
enumerates Jupyter/MCP/Ollama on prepared targets. Copy `llmhound.example.yaml`
to `llmhound.yaml` and replace the example scope/vantage and inputs for your
environment. Explicit flags replace only their own fields; omitted flags
preserve file values. See [configuration and limits](docs/reference/configuration.md)
for precedence, path resolution, strict input rules, policy bounds, and
reserved fields.

## Collection workflow

```bash
# Review what a scan would do (targets × checks), without touching targets
llmhound plan --config llmhound.yaml

# Scan; write an OpenGraph payload, evidence sidecar, and checkpoint journal
llmhound scan --config llmhound.yaml \
    --cidr 10.0.0.0/24 \
    --targets-file known-ai-hosts.txt \
    --output-dir ./out \
    --prefix llmhound-2026-09-29

# Register the extension schema, upload the payload, import saved queries (M3)
llmhound upload \
    --server https://bloodhound.corp.example \
    --token-file ~/.config/llmhound/bh-token \
    --payload ./out/llmhound-2026-09-29.json
```

`llmhound.yaml` holds the deployment scope, collection vantage, targets and
exclusions, rate/size bounds, sensitive-content opt-ins, TLS mode, User-Agent,
and Computer-correlation settings. Flags override it. `upload` remains an
honest not-implemented stub until M3.

TLS certificate verification is on by default. Record available certificate,
negotiated TLS, and verification metadata without bypassing a verification
failure. Only explicit `--insecure` permits unverified collection and must be
recorded in the evidence. Redirects are followed only within authorized target
scope and collection bounds.

## Operational model

The planned collector is designed to run unattended on a dedicated scanner VM,
on a cron or systemd schedule, feeding an automated BloodHound ingest pipeline:

- **Rate-limited.** Configurable concurrency, per-host rate limits, and
  connect/response timeouts.
- **Identifiable.** Requests carry a configurable
  `LLMHound/<version> (+contact)` User-Agent so defenders can attribute them.
- **Resumable.** Completed work is journaled; an interrupted scan picks up
  where it stopped.
- **Loss-tolerant.** An unreachable target or a failing collector degrades
  only that surface. An ingest-valid payload is always written, even when
  part of the scan fails.

## Responsible use

The future collector will actively probe and enumerate network services; the
current `targets` helper is offline. Only run it against
networks and systems you own or are explicitly authorized to assess. Collected
metadata (model catalogs, workspace file names, backend references) can be
sensitive; minimize and redact retained payloads, set retention limits, and
restrict access. Reading sensitive existing content such as system prompts,
configuration, or workspace files requires explicit opt-in. Advertised dependency URLs are evidence,
not permission to fetch arbitrary URLs.

## Roadmap

| Milestone         | Scope                                                                                                                                                  |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **M0**            | BloodHound CE compatibility spike against a pinned version: kind naming, property types, non-traversable edges, cleanup, edges to existing `Computer` |
| **M1**            | CLI skeleton, `llmhound.yaml`, graph model, OpenGraph emitter + evidence sidecar, extension schema; golden, identity, correlation, and semantics tests |
| **M2a**           | Discovery, checkpoint journal, `llmhound plan`, and the MCP, Ollama, and Jupyter collectors end-to-end                                              |
| **M2b**           | A2A, vLLM, LiteLLM, Qdrant, MLflow, Open WebUI, LangServe collectors under the [capability matrix](docs/reference/collector-capabilities.md)          |
| **M2c**           | Generic OpenAI-compatible endpoint, Ray dashboard, Langflow, Flowise, ChromaDB                                                                         |
| **M3**            | Resume, BloodHound CE API upload, saved queries, CE-API Computer lookup; adapter validation against an exact CE version/schema                       |
| **M4** _(future)_ | Credential-driven enumeration and access evidence                                                                                                      |
| **M5** _(future)_ | Node/edge description docs and an OpenGraph community library listing                                                                                  |

## Development validation

The [Go CI operator guide](docs/reference/go-ci.md) describes automated PR
checks, the module-free M0 bootstrap distinction, and how to trigger real
checks on existing QA PRs without changing their code.

## Licensing

LLMHound is original code written from scratch. Reference projects
(AgentHound, ShareHound, OpenHound, Netwrix AIHound) informed its behavior
only; no code is derived from them. See the
[provenance table](docs/plans/2026-09-29-llmhound-design.md#provenance-and-licensing-posture)
in the design doc.

LLMHound is licensed under [Apache-2.0](LICENSE).
