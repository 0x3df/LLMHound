# LLMHound

**Add AI infrastructure to your BloodHound attack paths with OpenGraph.**

LLMHound is a BloodHound [OpenGraph](https://bloodhound.specterops.io/opengraph/overview)
collector for LLM and agentic AI infrastructure: MCP servers, A2A agents, LLM
gateways, inference servers, vector stores, model registries, notebooks, and
AI UIs. It runs on a central collection server after SharpHound, AzureHound,
and your other collectors, scans your network remotely, and attaches what it
finds to the hosts already in your graph.

The question it helps answer is **"from this asset, what's the shortest attack
path to tier 0?"**, and, specifically:

- Which hosts running AI or MCP services sit on an attack path?
- What is the shortest path from a given asset to an AI host?
- Which AI hosts are close to tier 0, or anonymously reachable with an
  execution-capable surface?

LLMHound supplies the AI-service side of that join and the context around it.
It does not attribute assets or clean up stale data; your normalization
program does that, and LLMHound consumes its asset mapping. By default nothing
LLMHound emits is traversable: your existing AD and Azure edges provide the
paths. Opt-in rules may emit traversable edges only for cases that clear a
documented evidence bar (see [path qualification](docs/reference/graph-model.md#path-qualification-traversable-edges)).

```
asset mapping + targets → network scan → OpenGraph payload + evidence sidecar → AI services on your existing nodes
```

> [!NOTE]
> **Status: M0, M1 and the M2a slice are implemented on `QA`.** Offline
> `targets` and `plan`, plus `scan` for Jupyter, MCP, and Ollama, write
> OpenGraph payloads, evidence sidecars, and checkpoint journals. `upload`,
> resume, and the remaining surfaces are later milestones. The implemented
> code follows an earlier model (`CollectionVantage`, access edges, suffix
> correlation, content opt-ins off); this README and the
> [design](docs/plans/2026-09-29-llmhound-design.md) describe the **target**,
> and the [implementation delta](docs/reference/graph-model.md#implementation-delta)
> lists where the code differs. See [configuration](docs/reference/configuration.md),
> the [M2a integration note](docs/reference/m2a-integration.md), the
> [M0 lab](lab/README.md), and the [Roadmap](#roadmap).

## Contents

- [What it finds](#what-it-finds)
- [How it works](#how-it-works)
- [BloodHound integration](#bloodhound-integration)
- [Quick start](#quick-start)
- [Collection workflow](#collection-workflow)
- [Operational model](#operational-model)
- [Responsible use](#responsible-use)
- [Roadmap](#roadmap)
- [Development validation](#development-validation)
- [Licensing](#licensing)

## What it finds

v1 collection is **anonymous, bounded, and read-only**: LLMHound sends no
credentials and uses only allowlisted, read-only operations. Within that
policy it collects as much path-relevant context as it can: identity and
version, advertised and observed authentication, execution-capable surfaces,
backend and storage references, inventory, and TLS. Each value is labeled
`observed`, `declared`, or `inferred`, and unknown stays unknown. It also reads
existing content a service hands out anonymously in a single allowlisted read
(system prompts, configuration, notebook and flow bodies, bounded vector
samples), within size caps. Exposed secrets are reported only as a presence
flag, never a value, and only when a high-precision detector is certain;
otherwise the field stays unset. Content bodies go to a separate restricted
file, never into the graph. LLMHound never guesses, tests, or uses credentials.
(The content tier and secret detection are target design; the M2a collectors
currently collect metadata only.) The
[capability matrix](docs/reference/collector-capabilities.md)
defines each surface's checks; availability varies by product, version, and
deployment, so collection is not guaranteed.

| Surface        | What v1 collects                                                                                                  |
| -------------- | ----------------------------------------------------------------------------------------------------------------- |
| **MCP**        | Server identity/capabilities, protocol metadata, tool schemas and capability hints, resource and prompt descriptors |
| **A2A**        | Agent-card identity, skills, capabilities, interfaces, and advertised authentication requirements                 |
| **Ollama**     | Served-model metadata, digests, advertised model provenance, and modelfiles/system prompts                        |
| **vLLM**       | Server fingerprint, served-model metadata, and advertised deployment details                                      |
| **LiteLLM**    | Gateway fingerprint, model catalog, redacted backend references, and configuration                                |
| **Qdrant**     | Vector-collection metadata, point counts, schema context, and bounded payload samples                             |
| **MLflow**     | Experiment and registered-model metadata, model provenance, and artifact-store references                        |
| **Jupyter**    | Authentication posture, session metadata, kernel/terminal exposure, workspace listings, and bounded file bodies   |
| **Open WebUI** | Instance fingerprint, advertised backend references, and configuration                                            |
| **LangServe**  | App fingerprint, advertised runnable inventory, and input/output schema metadata                                  |

Planned after the core ten (M2c): a generic **OpenAI-compatible** endpoint kind
(llama.cpp, TGI, LM Studio, LocalAI, SGLang when the product cannot be proven),
**Ray dashboard**, **Langflow**, **Flowise**, and **ChromaDB**.

LLMHound is network-only. It does not read local files, agent configs, or
keychains on the machine it runs on or on any target.

## How it works

1. **Targets.** CIDR ranges and/or a targets file of IPs and FQDNs,
   deduplicated.
2. **Discovery.** Data-driven HTTP path fingerprints (`internal/discovery`)
   type services on known default ports; definitions are embedded and
   overridable via `--discovery-file`. A scan probes each configured surface
   once and collects only on a match; unreachable or unmatched surfaces are
   journaled as failed coverage.
3. **Enumeration.** A read-only collector per surface. Each records coverage
   (`complete`, `partial`, `failed`, `truncated`) and, per check, an outcome
   (`success`, `denied`, `unsupported`, `failed`, `skipped`) with a reason.
4. **Attachment.** Each target is looked up in the asset mapping supplied by
   your normalization program and attached to the existing BloodHound node
   (Computer, Azure VM, and so on) by objectid. An unmapped target becomes a
   `NetworkEndpoint` for the normalizer to attribute later.
5. **Classification.** Authentication posture, execution surface, and
   dependencies are recorded as flat, queryable properties.
6. **Emission.** One OpenGraph payload (JSON, or a ZIP stream for large scans)
   plus an `.evidence.jsonl` sidecar. Deterministic IDs include deployment
   scope; rescans retain identity.
7. **Upload.** Register the schema, upload the payload, and import saved
   queries through the BloodHound CE API, or let your existing ingest pick up
   the files.

## BloodHound integration

Targets **BloodHound CE with PostgreSQL**. Support requires validation of the
exact CE version, OpenGraph schema, and API capabilities.

- **Extension schema.** `extension/schema.json` registers `LLMHound_`-prefixed
  kinds (for example `LLMHound_OllamaInstance`), as CE 9.7.1 requires.
- **Attached to your existing nodes.** `ObservedAt` links a service to the node
  it was mapped to. Attachment is an edge, not an identity merge; LLMHound never
  overwrites native BloodHound IDs or emits native node kinds.
- **Access as properties.** Anonymous access, authentication posture, and
  execution surface are properties on the service, so they are filterable in
  any query, including your existing tier-0 queries.
- **Traversability.** Off by default. Opt-in rules may add `CanExecuteOn`
  edges only where documented product semantics plus observed anonymous
  evidence qualify. See the bar in the graph model.
- **Provenance and upload shape.** LLMHound-owned nodes and edges are tagged
  `source_kind` `LLMHound` with scan ID, vantage key, and observation time.
  Edges to your existing nodes go in a separate linking payload **without**
  `source_kind`, because CE 9.7.1 would otherwise tag your Computers and delete
  them on source cleanup. Reconciliation and cleanup of those links belong to
  your normalizer.
- **Starter queries.** Saved Cypher searches in `extension/saved_searches/`,
  led by the tier-0 pathing questions; see the
  [planned list](docs/reference/saved-queries.md).

The node and edge model, identity, and property contract are in
[`docs/reference/graph-model.md`](docs/reference/graph-model.md).

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
bounded IP/FQDN/CIDR inputs, deduplicates, removes exact-name/IP/CIDR
exclusions, and prints sorted targets without DNS or target traffic. `plan`
prints the allowlisted check inventory without contacting targets. `scan`
discovers and enumerates Jupyter/MCP/Ollama on prepared targets. Copy
`llmhound.example.yaml` to `llmhound.yaml` and replace the example
scope/vantage and inputs. Explicit flags replace only their own fields. See
[configuration and limits](docs/reference/configuration.md) for precedence,
path resolution, strict input rules, and policy bounds.

## Collection workflow

```bash
# Review what a scan would do (targets × checks), without touching targets
llmhound plan --config llmhound.yaml

# Scan; write an OpenGraph payload, evidence sidecar, and checkpoint journal
llmhound scan --config llmhound.yaml \
    --cidr 10.20.30.0/24 \
    --targets-file known-ai-hosts.txt \
    --output-dir ./out \
    --prefix llmhound-2026-11-20

# Register the extension schema, upload the payload, import saved queries (M3)
llmhound upload \
    --server https://bloodhound.corp.example \
    --token-file ~/.config/llmhound/bh-token \
    --payload ./out/llmhound-2026-11-20.json
```

`llmhound.yaml` holds the deployment scope, vantage key, targets and
exclusions, rate/size bounds, TLS mode, User-Agent, and the asset-mapping path
(`correlation.mapping_file`). The target design adds content and
secret-detector settings and any enabled path-qualification rules (see the
[implementation delta](docs/reference/graph-model.md#implementation-delta)).
Flags override the file. `upload` remains an honest not-implemented stub until
M3.

TLS certificate verification is on by default. Verification metadata is
recorded without bypassing a failure; only explicit `--insecure` permits
unverified collection, and that is recorded in the evidence. Redirects are
followed only within authorized target scope.

## Operational model

LLMHound is built to run unattended on a dedicated scanner VM, on a cron or
systemd schedule, after your AD and Azure collection:

- **Rate-limited.** Configurable concurrency, per-host rate limits, and
  connect/response timeouts.
- **Identifiable.** Requests carry a configurable
  `LLMHound/<version> (+contact)` User-Agent.
- **Resumable.** Completed work is journaled; an interrupted scan picks up
  where it stopped, retaining original observation times.
- **Loss-tolerant.** A failing target or collector degrades only that surface.
  An ingest-valid payload is always written.

## Responsible use

LLMHound actively probes and enumerates network services. Only run it against
networks and systems you own or are explicitly authorized to assess. Collected
metadata (model catalogs, workspace file names, backend references) can be
sensitive; minimize and redact retained payloads, set retention limits, and
restrict access. The content file (`.content.jsonl`) can hold system
prompts, configuration, and file bodies: keep it out of the BloodHound ingest
path, restrict access, and set retention limits. Secret values are never
stored. Workspace listings and the whole content tier
can be disabled in configuration. Advertised dependency URLs are evidence, not
permission to fetch arbitrary URLs. Tool and prompt descriptions come from the
scanned service: treat them as untrusted input, including in any LLM tooling
downstream of the graph.

## Roadmap

| Milestone         | Scope                                                                                                                                           |
| ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| **M0** _(done)_   | CE 9.7.1 compatibility spike and reproducible `lab/`; follow-ups R1–R9 (tier-0 tags, path performance, AzureHound nodes, traversable rule edges) are open |
| **M1** _(done, earlier model)_ | CLI skeleton, `llmhound.yaml`, graph model, mapping-file attachment, emitter + sidecar, content file and secret-detector framework, property contract, extension schema; golden, identity, and attachment tests |
| **M2a** _(done, earlier model)_ | Discovery, checkpoint journal, `llmhound plan`, the MCP, Ollama, and Jupyter collectors end-to-end, and the first secret detectors                 |
| **M2b**           | A2A, vLLM, LiteLLM, Qdrant, MLflow, Open WebUI, LangServe collectors under the [capability matrix](docs/reference/collector-capabilities.md)   |
| **M2c**           | Generic OpenAI-compatible endpoint, Ray dashboard, Langflow, Flowise, ChromaDB                                                                  |
| **M2d**           | Path-qualification rules: opt-in traversable edges for cases that clear the evidence bar                                                        |
| **M3**            | Resume, BloodHound CE API upload, saved queries; adapter validation against an exact CE version/schema                                         |
| **M4** _(future)_ | Credential-driven enumeration and richer evidence                                                                                               |
| **M5** _(future)_ | Node/edge description docs and an OpenGraph community library listing (secondary goal)                                                          |

## Development validation

The [Go CI operator guide](docs/reference/go-ci.md) describes automated PR
checks, the module-free M0 bootstrap distinction, and how to trigger real
checks on existing QA PRs without changing their code.

## Licensing

LLMHound is original code written from scratch. Reference projects
(AgentHound, ShareHound, OpenHound, Netwrix AIHound) informed its behavior
only; no code is derived from them. See the
[provenance table](docs/plans/2026-09-29-llmhound-design.md#provenance-and-licensing-posture).

LLMHound is licensed under Apache-2.0 (see [`LICENSE`](LICENSE)).
