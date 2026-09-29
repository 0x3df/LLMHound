# LLMHound — project context for agents

Read this first. It captures the full decision trail from the founding design
sessions so any agent can pick up work without re-deriving context.

## Mission

Build **LLMHound**: a BloodHound OpenGraph collector that remotely maps the
attack surface of LLM and agentic AI infrastructure from a central
collection server, feeding an existing **BloodHound Community Edition (v8+,
PostgreSQL)** instance. Goal: eventually listed on the SpecterOps OpenGraph
community library page (https://bloodhound.specterops.io/opengraph/library).

- **Remote network collection only.** No host-local scanning (agent configs,
  env vars, keychains, instruction files) — explicitly rejected. Runs on a
  dedicated scanner VM as part of an automated ingest pipeline.
- **v1 is anonymous, read-only enumeration.** No service credentials yet.
  Credential-driven enumeration is milestone M4.
- **Single language/binary: Go.** Single static `llmhound` binary.

## Canonical documents

| Doc | Role |
|---|---|
| `docs/plans/2026-09-29-llmhound-design.md` | Approved design — architecture, graph model, behavior, testing, milestones. **Source of truth.** |
| `docs/reference/graph-model.md` | Full node/edge reference (draft). |
| `README.md` | Public-facing overview (library-page ready). |
| `extension/schema.json`, `extension/saved_searches/` | Not yet created (M1). |

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
   `modelcontextprotocol/go-sdk`) are fine.
3. **Naming:** `LLMHound` (namespace `LLMHound`, source_kind `LLMHound`).
   Checked clean against GitHub and the OpenGraph library listing.
   Rejected as taken: AgentHound (reference project), MCPHound (3 existing
   MCP scanners), AIHound (Netwrix extension), PromptHound, ContextHound,
   AgenticHound. A single extension covers all surfaces (an LLMHound/MCP
   split was considered and declined).
4. **Graph model:** `LLMHound_*`-namespaced kinds per `docs/reference/graph-model.md`.
   Topology edges non-traversable; only access evidence
   (`LLMHound_PublicAccess`, `LLMHound_UnauthenticatedAccess`) traverses.
   Deterministic SHA-256 objectids. Hybrid AD bridging via property match
   (`name` = FQDN) against existing `Computer` nodes.
5. **Reference environment:** BloodHound CE on PostgreSQL; upload via API
   (`POST /api/v2/login`, `PUT /api/v2/extensions`, `POST /api/v2/file-upload`,
   `POST /api/v2/saved-queries`) or manual/UI ingest of emitted files.

## Reference materials (local paths & URLs)

- `~/Projects/references/agenthound` — AgentHound clone. Rich behavioral
  reference for per-surface enumeration, identity semantics, honest
  coverage outcomes (`complete`/`partial`/`failed`). Its
  `docs/reference/graph-model.md` informed our kind vocabulary. Read-only
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

1. **M1 — Skeleton + graph + emitter:** CLI (cobra), targets loading,
   graph model, OpenGraph emitter, `extension/schema.json`, golden-file
   tests. *Next up.*
2. **M2 — Discovery + collectors:** port/path discovery; anonymous
   enumeration of all 10 surfaces (MCP, A2A, Ollama, vLLM, LiteLLM, Qdrant,
   MLflow, Jupyter, Open WebUI, LangServe).
3. **M3 — Checkpoint + upload:** journal/resume, CE API client,
   saved queries, end-to-end against a CE instance.
4. **M4 (future) — Credentials:** authenticated enumeration, access evidence.
5. **M5 (future) — Library listing:** description docs per node/edge kind,
   submission to `SpecterOps/bloodhound-docs` "Library Change" issue.

## Working conventions

- Repo: `~/Projects/LLMHound` (a legacy symlink `~/Projects/AIHound` →
  `LLMHound` may exist; the directory was renamed mid-session).
- Branch `main`; small committed steps; docs live under `docs/`.
- Target ports for discovery (baseline): Ollama 11434, vLLM 8000,
  MLflow 5000, Jupyter 8888, Qdrant 6333, Open WebUI 3000/8080,
  LiteLLM 4000, MCP/A2A on 80/443/8080 + well-known paths.
- Design decisions follow the brainstorming-first process: design docs in
  `docs/plans/` before code.
