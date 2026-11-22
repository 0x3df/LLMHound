# AGENTS.md — operating manual for LLMHound

Humans: read [README.md](README.md). This file is for coding agents. It states what is
non-negotiable and where truth lives; it does not repeat what the code or docs already show.

## Mission

LLMHound is a Go collector that remotely, **anonymously, and read-only** maps LLM/agentic-AI
services and attaches them to hosts already in a BloodHound CE graph (SharpHound, then
AzureHound), to improve answers to "from this asset, what is the shortest attack path to
tier 0?". A separate normalization program owns attribution and cleanup; LLMHound consumes its
asset mapping. Why and for whom: [executive summary](docs/00-executive-summary.md).

## Orient in 60 seconds

| You need | Read |
|---|---|
| Intent, scope, architecture | [docs/01-design.md](docs/01-design.md) |
| Node/edge kinds, identity, properties, content/secrets, path qualification, what is built vs specified | [docs/02-graph-model.md](docs/02-graph-model.md) (**canonical**) |
| Per-surface checks and outcome contract | [docs/03-collector-capabilities.md](docs/03-collector-capabilities.md) (**canonical**) |
| The queries the product exists to answer | [docs/04-saved-queries.md](docs/04-saved-queries.md) |
| Measured BloodHound CE 9.7.1 behavior | [docs/05-ce-compatibility.md](docs/05-ce-compatibility.md) |
| What to build next, with exit criteria | [docs/06-roadmap.md](docs/06-roadmap.md) |
| Why a decision was made | [docs/07-decisions.md](docs/07-decisions.md) |
| Flags, YAML, mapping file | [docs/guides/configuration.md](docs/guides/configuration.md) |
| Build, test, CI, lab | [docs/guides/development.md](docs/guides/development.md) |
| Full index | [docs/README.md](docs/README.md) |

## Commands

```bash
CGO_ENABLED=0 go build -o llmhound ./cmd/llmhound
gofmt -l . && go vet ./... && go test -race ./...    # all must pass; includes ./docs
UPDATE_GOLDEN=1 go test ./internal/emitter -run TestGoldenEmission   # then review the diff
```

## Repo map

`cmd/llmhound` CLI · `internal/config` YAML + flags · `internal/targets` target prep ·
`internal/discovery` data-driven fingerprints · `internal/transport` bounded TLS-aware HTTP ·
`internal/collectors/<surface>` one package per surface (jupyter, mcp, ollama, a2a, vllm, qdrant,
litellm, mlflow, openwebui, langserve, openaicompat, ray, langflow, flowise, chromadb) · `internal/content`
bounded content-tier records + 0600 writer · `internal/secrets` high-precision
secret detectors over content bodies · `internal/correlate` mapping → existing
native node or `NetworkEndpoint` · `internal/graph` identity, kinds, observations, edges,
access summary · `internal/rules` & `extension/rules` opt-in traversable rule engine ·
`internal/evidence` sidecar records · `internal/emitter` base + linking payloads ·
`internal/bloodhound` CE API client, pre-flight, two-step uploader & gate ·
`internal/checkpoint` journal/replay · `internal/savedsearch` CE saved queries
(`extension/saved_searches/`, `tools/gensearches`) · `internal/scanner` orchestration ·
`extension/schema.json` · `lab/` CE lab · `legacy/` retired, never built.

## Invariants (do not break; each has a test or a decision behind it)

**Collection safety**
1. Anonymous and read-only. Never send, guess, test, validate, or use a credential. Never call a
   mutating or workload-starting operation (tool call, prompt, inference, job submit). Validate
   operation semantics, not just the HTTP verb.
2. TLS verification is on; a failure stops collection. Only explicit `--insecure` bypasses it, and
   it is recorded. Recheck authorization on every redirect hop; advertised URLs are evidence, not
   permission to fetch.
3. Everything is bounded (time, pages, items, bytes). Hitting a bound records `truncated`.
4. Descriptions, annotations, and banners from a scanned service are **untrusted input**.
5. Secrets are never stored: a boolean and a type only, and only from structure-verified
   detectors with zero-false-positive corpora. Content bodies go to a restricted file, never the graph.

**Graph contract**
6. Emitted kinds are `LLMHound_<Kind>`; code uses logical names via `internal/graph/kinds.go`.
   Property names are flat, lowercase, primitive (or homogeneous primitive arrays). CE upper-cases
   node ids and `name`, so case-sensitive data never goes in `name`.
7. Nothing is traversable unless an opt-in rule clears the six-point bar in the graph model.
   `CanExecuteOn` and `CanAssumePrincipal` are the only traversable edge kinds (`EdgeKind.IsTraversable()`), gated behind `path_qualification.enabled_rules` (empty by default).
8. Attach to **existing** nodes by objectid and native kind only, from the asset mapping. No DNS,
   suffix, or CE-side guessing. Never emit or modify a native-kind node. Native IDs are verbatim.
9. **Two payloads.** Owned nodes/edges carry `source_kind: LLMHound`. Edges touching native nodes go
   in a separate payload **without** it (a `source_kind` payload tags referenced nodes and source
   cleanup then deletes them; M0 Q5). A missing endpoint creates a stub node, so existence must be
   verified before upload.
10. Anonymous access is **properties** on the service (`auth_observed`, `anon_operations`,
    `vantage_key`), never edges, and only enumeration-class checks count (Jupyter version metadata
    never does).

**Epistemics**
11. Precision over recall. Unknown stays unknown; a boolean is set only on deterministic evidence;
    absence is never a claim. Label values observed / declared / inferred.
12. A 404 alone is ambiguous, not "unsupported". Check outcome and surface coverage are independent.
13. **Provenance:** 100% original code. Reference repos (AgentHound, ShareHound, OpenHound, Netwrix
    AIHound) are behavioral only. Never paste their code.

## Playbooks

### Adding a collector
1. Add its row and checks to the [capability matrix](docs/03-collector-capabilities.md) first.
2. Package under `internal/collectors/<surface>`; add a discovery definition in `internal/discovery`.
3. Use `internal/transport`; record an outcome and reason for **every** check; derive access via
   `graph.SummarizeAccess` from the surface's enumeration checks only.
4. Build the service node with the `AIService` label; attach with `correlate.Resolver`
   (a nil resolver is valid and falls back to `NetworkEndpoint`); never read content beyond
   documented bounds.
5. Tests with `httptest` fixtures for success, denied, unsupported/ambiguous, malformed, truncated,
   TLS failure, and redirect scope. No external network.
6. Wire it into `internal/scanner`; update `docs/collectors/` (page + index), the roadmap row, and
   the [implementation status](docs/02-graph-model.md#implementation-status).

### Changing the graph, properties, or schema
Edit `internal/graph`, `extension/schema.json` (the schema test enforces agreement), regenerate
goldens deliberately, and update [docs/02-graph-model.md](docs/02-graph-model.md) in the same change.

### Changing docs
One canonical home per rule (decision 17): link, don't restate. Add new numbered docs to
[docs/README.md](docs/README.md). Retire rather than delete: move to `legacy/` with an ARCHIVED
banner. `go test ./docs` enforces links, anchors, the index, and banners.

### Recording a decision
Add a row to [docs/07-decisions.md](docs/07-decisions.md); supersede, don't erase.

## Conventions

- Go: `gofmt`, wrapped errors with context, no panics on input, context-aware and bounded I/O.
- Tests live beside code; fixtures are local `httptest` servers or `testdata/`; goldens define the
  emitted contract, so review their diffs.
- Branches: `QA` is the integration branch; PRs target `QA`. Small, reviewable commits; no
  force-push on shared branches. Commit bodies explain *why*.
- Behavior and docs change together. If you touch a "specified, not built" row, update the status table.

## State and next work

Do not duplicate it here: current status is the [implementation
status](docs/02-graph-model.md#implementation-status) and the ordered backlog is the
[roadmap](docs/06-roadmap.md). Measured BloodHound behavior, including the R1–R9 follow-ups, is in
[docs/05-ce-compatibility.md](docs/05-ce-compatibility.md).

## Maintaining this file

Keep this file for knowledge useful to almost every future agent session in this project. Do not
repeat what the codebase already shows; point to the authoritative file or command instead. Prefer
rewriting or pruning existing entries over appending new ones. When updating this file, preserve
this bar for all agents and keep entries concise.
