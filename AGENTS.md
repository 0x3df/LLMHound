# LLMHound — project context for agents

Read this first. It captures the full decision trail from the founding design
sessions so any agent can pick up work without re-deriving context.

## Mission

Build **LLMHound**: a BloodHound OpenGraph collector that remotely maps the
attack surface of LLM and agentic AI infrastructure from a central
collection server. It extends an existing **BloodHound Community Edition
(PostgreSQL)** buildout: observed AI services attach to the AD `Computer`
nodes already in the graph wherever a target can be correlated. Support is
declared only for an exact CE version/schema validated by the adapter gate.
Goal: eventually listed on the SpecterOps OpenGraph community library page
(https://bloodhound.specterops.io/opengraph/library).

- **Remote network collection only.** No host-local scanning (agent configs,
  env vars, keychains, instruction files) — explicitly rejected. Runs on a
  dedicated scanner VM as part of an automated ingest pipeline.
- **v1 is anonymous, read-only enumeration.** No service credentials yet.
  Credential-driven enumeration is milestone M4.
- **Single language/binary: Go.** Single static `llmhound` binary.

## Canonical documents

| Doc | Role |
|---|---|
| `docs/plans/2026-09-29-llmhound-design.md` | Approved design — architecture, behavior, testing, milestones. **Source of truth.** |
| `docs/reference/graph-model.md` | Node/edge kinds, identity, Computer correlation, evidence contract. |
| `docs/reference/collector-capabilities.md` | Per-surface allowlisted checks and per-check outcome contract. |
| `docs/reference/ce-compatibility.md` | M0 spike questions and recorded CE answers. |
| `docs/reference/saved-queries.md` | Starter saved queries (drive which properties must be queryable). |
| `README.md` | Public-facing overview; implemented CLI vs planned collector behavior. |
| `docs/reference/configuration.md` | Working CLI/configuration/target-input and M2a plan/scan contract, limits, build and test commands. |
| `docs/reference/m2a-integration.md` | M2a live CLI vs unit-test coverage and remaining gaps. |
| `docs/plans/.future/` | Parked ideas only. Not a roadmap; nothing there is in scope. |
| `extension/schema.json` | OpenGraph extension schema (M1). `extension/saved_searches/` is not yet created (M3). |

## Decisions already made (do not relitigate without cause)

1. **Approach:** pure Go, modeled on ShareHound's Go architecture (targets →
   discovery → worker pool → checkpoint → OpenGraph emission), with the
   collection *behavior* informed by AgentHound. Not OpenHound (Python/DLT),
   not a hybrid, not a fork/wrapper of AgentHound.
2. **Provenance — critical constraint:** LLMHound contains **100% original
   code**. AgentHound (Apache-2.0), ShareHound (unlicensed), Netwrix AIHound
   (MIT), and OpenHound are behavioral references only — no code copied. This
   was a deliberate choice to avoid attribution/licensing entanglement. Do
   not paste code from any reference repo. Normal public Go deps (cobra,
   `modelcontextprotocol/go-sdk`) are fine. LLMHound itself is **Apache-2.0**.
3. **Naming:** `LLMHound` (extension/source identifier and `source_kind`
   `LLMHound`). Checked clean against GitHub and the OpenGraph library listing.
   Rejected as taken: AgentHound (reference project), MCPHound (3 existing
   MCP scanners), AIHound (Netwrix extension), PromptHound, ContextHound,
   AgenticHound. A single extension covers all surfaces (an LLMHound/MCP
   split was considered and declined). Code uses clean logical names;
   M0 requires emitted `LLMHound_<Kind>` names on CE 9.7.1. The central
   mapping is `internal/graph/kinds.go`; details are in `ce-compatibility.md`.
4. **Graph model** per `docs/reference/graph-model.md`: **all v1 edges are
   non-traversable**, including access evidence (`UnauthenticatedAccess`,
   `PublicAccess`, from a `CollectionVantage`). Deterministic SHA-256
   objectids scoped by deployment. **Computer correlation:** services attach
   via `ObservedAt` to an existing AD `Computer` when a target correlates
   (mapping file → configured AD-suffix FQDN match → CE API lookup);
   otherwise to a fallback `NetworkEndpoint` node. Correlation is an edge to
   an existing node, never an identity merge; native BloodHound IDs are never
   overwritten. M0 Q5 requires native-linking payloads **without source_kind**
   to prevent source cleanup from deleting Computers; see `ce-compatibility.md`.
5. **Reference environment:** BloodHound CE on PostgreSQL at a pinned,
   validated version; upload via API (`POST /api/v2/login`,
   `PUT /api/v2/extensions`, `POST /api/v2/file-upload`,
   `POST /api/v2/saved-queries`) or manual/UI ingest of emitted files.
6. **Outputs:** each scan emits an OpenGraph payload plus an
   `.evidence.jsonl` sidecar (per-check results, fingerprints, TLS, redirects,
   correlation decisions). Configuration lives in `llmhound.yaml`; flags
   override it.
7. **Deferred:** change comparisons / `llmhound diff` (see `.future`).

## Reference materials (local paths & URLs)

- `~/Projects/references/agenthound` — AgentHound clone. Rich behavioral
  reference for per-surface enumeration, identity semantics, honest
  coverage outcomes (`complete`/`partial`/`failed`). Read-only
  inspiration; never copy code.
- `/tmp/og/` (may be stale) — pulled SpecterOps OpenGraph developer docs:
  `dev-graph-data.md` (payload format), `dev-graph-definition.md`
  (extension schema), `dev-nodes.md`, `dev-edges.md`, `dev-metadata.md`.
  Re-fetch from `https://bloodhound.specterops.io/opengraph/developer/<page>.md`
  (also `_llms/blood-hound.md` and `llms-full.txt` indexes).
- `/tmp/sharehound`, `/tmp/openhound`, `/tmp/openhound-okta`,
  `/tmp/netwrix-aihound`, `/tmp/tailscalehound` — cloned reference repos
  (architectural examples only).
- Key online docs: OpenGraph overview/faq/developer pages; the library page
  lists every existing `___Hound` extension (check names against it).

## Milestones

0. **M0 — CE compatibility spike:** pinned CE in docker-compose; toy
   extension + payload; answer the questions in `ce-compatibility.md`
   (kind namespacing, multi-label, property types, non-traversable edges,
   `source_kind` cleanup, property-matched edges to `Computer`). **Complete:**
   CE 9.7.1 findings and safe upload constraints are in `ce-compatibility.md`.
1. **M1 — Skeleton + graph + emitter:** CLI (cobra), `llmhound.yaml` loader,
   targets, graph model, OpenGraph emitter + evidence sidecar,
   `extension/schema.json`, `LICENSE`, golden-file tests.
2. **M2a — Vertical slice:** discovery, checkpoint journal interface, and
   MCP, Ollama, Jupyter collectors end-to-end to payload. **Complete on QA
   path:** `llmhound plan`/`scan` wired via `internal/scanner`; see
   `docs/reference/m2a-integration.md` for live vs unit coverage and gaps.
3. **M2b — Remaining core surfaces:** A2A, vLLM, LiteLLM, Qdrant, MLflow,
   Open WebUI, LangServe.
4. **M2c — Long tail:** generic `OpenAICompatibleEndpoint`, Ray dashboard,
   Langflow, Flowise, ChromaDB.
5. **M3 — Resume + upload:** resume, CE API client, saved queries, CE-API
   Computer lookup, adapter validation gate.
6. **M4 (future) — Credentials:** authenticated enumeration, access evidence.
7. **M5 (future) — Library listing:** description docs per node/edge kind,
   submission to `SpecterOps/bloodhound-docs` "Library Change" issue.

## Working conventions

- Repo: `~/Projects/LLMHound` (a legacy symlink `~/Projects/AIHound` →
  `LLMHound` may exist; the directory was renamed mid-session).
- Integration branch `QA` for implementation; PRs target `QA`, not `main`.
  Small committed steps; docs live under `docs/`.
- CLI/input and M2a scan orchestration: `docs/reference/configuration.md`
  and `docs/reference/m2a-integration.md`. `targets` and `plan` are offline;
  `scan` enumerates Jupyter/MCP/Ollama; `upload`/resume remain M3 stubs.
- Discovery ports/paths are data-driven fingerprint definitions (embedded,
  overridable via `--discovery-file`). Baseline: Ollama 11434, vLLM 8000,
  MLflow 5000, Jupyter 8888, Qdrant 6333, Open WebUI 3000/8080, LiteLLM 4000,
  MCP/A2A on 80/443/8080 + well-known paths.
- Design decisions follow the brainstorming-first process: design docs in
  `docs/plans/` before code.
- M0 CE-compatibility answers (kind naming, property types, upload pipeline,
  cleanup semantics) are recorded in `docs/reference/ce-compatibility.md`;
  the reproducible lab and check suite live in `lab/` (see `lab/README.md`).
- Graph, correlation, and OpenGraph/evidence emission: `docs/reference/graph-model.md`.
  Test locally without external targets: `go test -race ./...` and `go vet ./...`.

## Maintaining this file

Keep this file for knowledge useful to almost every future agent session in this project.
Do not repeat what the codebase already shows; point to the authoritative file or command instead.
Prefer rewriting or pruning existing entries over appending new ones.
When updating this file, preserve this bar for all agents and keep entries concise.
