# LLMHound — project context for agents

Read this first. It captures the full decision trail from the founding design
sessions so any agent can pick up work without re-deriving context.

## Mission

Build **LLMHound**: a BloodHound OpenGraph collector that remotely maps the
attack surface of LLM and agentic AI infrastructure from a central
collection server. **Primary goal: enrich an existing corporate attack-path
program** (SharpHound first, then AzureHound, etc.) that answers "from this
asset, what's the shortest attack path to tier 0?" LLMHound maps on top of
infrastructure those collectors already identified, and adds any context that
helps that process (AI hosts on paths, shortest path to an AI host, AI hosts
near tier 0, anonymously reachable hosts with execution surfaces). A separate
**normalization program** owns asset attribution and cleanup/reconciliation;
LLMHound consumes its asset mapping. It extends an existing **BloodHound
Community Edition (PostgreSQL)** buildout. Support is declared only for an exact
CE version/schema validated by the adapter gate. Secondary goal: eventually
listed on the SpecterOps OpenGraph community library page
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
| `docs/plans/2026-09-29-llmhound-design.md` | Design (revised draft) — purpose, architecture, behavior, testing, milestones. **Source of truth for architecture and milestones.** |
| `docs/reference/graph-model.md` | Node/edge kinds, identity, attachment, flat property contract, path qualification. **Canonical for the model.** |
| `docs/reference/collector-capabilities.md` | Per-surface allowlisted checks and per-check outcome contract. |
| `docs/reference/ce-compatibility.md` | M0 spike questions and recorded CE answers. |
| `docs/reference/saved-queries.md` | Starter saved queries (drive which properties must be queryable). |
| `README.md` | Public-facing overview. |
| `docs/plans/.future/` | Parked ideas only. Not a roadmap; nothing there is in scope. |
| `extension/schema.json`, `extension/saved_searches/` | Not yet created (M1/M3). |

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
   split was considered and declined). Kinds use clean logical names
   (`OllamaInstance`, `ProvidesModel`) with no blanket prefix; whether any
   qualification is needed is decided by the M0 spike and recorded in
   `ce-compatibility.md`.
4. **Graph model** per `docs/reference/graph-model.md`. **Nothing is
   traversable by default**; the existing AD/Azure edges provide paths and
   LLMHound supplies the AI-service target set and context. A traversable edge
   (`CanExecuteOn`) may be emitted only by an opt-in, documented rule that
   clears the six-point path-qualification bar. Otherwise the goal is maximum
   flat, queryable data (min-max): identity/version, auth posture, execution
   surface, dependencies, inventory, TLS, each labeled observed/declared/
   inferred. Anonymous access is **properties**, not edges; there is no
   `CollectionVantage` node. Deterministic SHA-256 objectids scoped by
   deployment. **Attachment:** services attach via `ObservedAt` to an existing
   BloodHound node of any kind (Computer, AZVM, …) using an externally supplied
   asset mapping (target → objectid + kind); unmapped targets get a fallback
   `NetworkEndpoint` for the normalizer. No suffix/reverse-DNS/CE-lookup
   matching in LLMHound. Attachment is an edge, never an identity merge; native
   IDs are never overwritten and native-kind nodes are never emitted.
5. **Reference environment:** BloodHound CE on PostgreSQL at a pinned,
   validated version; upload via API (`POST /api/v2/login`,
   `PUT /api/v2/extensions`, `POST /api/v2/file-upload`,
   `POST /api/v2/saved-queries`) or manual/UI ingest of emitted files.
6. **Outputs:** each scan emits an OpenGraph payload plus an
   `.evidence.jsonl` sidecar (per-check results, fingerprints, TLS, redirects,
   attachment decisions) and a restricted `.content.jsonl`. Configuration lives in `llmhound.yaml`; flags
   override it.
7. **Deferred:** change comparisons / `llmhound diff` (see `.future`).
   Reconciliation and cleanup are the normalizer's job, not LLMHound's.
8. **Content and secrets:** the content tier (system prompts, config, file/flow
   bodies, bounded samples) is collected **by default** when one anonymous
   allowlisted read returns it, within byte/item caps; bodies go only to a
   restricted `.content.jsonl`. Secrets are **boolean only**
   (`has_exposed_secret` true-or-unset, `secret_types`): the value is discarded
   at detection and stored nowhere. Detection is **precision-only**: false
   positives are unacceptable in this environment, so only deterministic,
   structure-verified detectors with zero-FP corpora may set the flag; no
   entropy/keyword heuristics; unset never means clean. Positive claims
   generally are precision-first; ambiguous stays unknown. LLMHound never
   guesses, tests, validates, or uses credentials (M4). See
   `graph-model.md#content-and-secrets`.
9. **Sequencing:** M0 (CE spike) runs before further model design. The model
   docs are a draft until `ce-compatibility.md` is answered.
10. **Doc ownership:** one canonical home per rule — model, property contract,
    content/secrets, and path qualification in `graph-model.md`; checks and
    outcomes in `collector-capabilities.md`. Other docs link; do not restate.

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

0. **M0 — CE compatibility spike:** pinned CE in docker-compose with
   SharpHound/AzureHound sample data; toy extension + payload; answer the
   questions in `ce-compatibility.md` (kind namespacing, multi-label, array
   properties, traversable/non-traversable behavior in pathfinding and raw
   Cypher, attachment by objectid, missing-node behavior, tier-0 tags, query
   performance). *Next up.*
1. **M1 — Skeleton + graph + emitter:** CLI (cobra), `llmhound.yaml` loader,
   targets, graph model, mapping-file attachment, OpenGraph emitter + evidence
   sidecar, content file + secret-detector framework, property contract,
   `extension/schema.json`, `LICENSE`, golden-file tests.
2. **M2a — Vertical slice:** discovery, checkpoint journal interface, and
   MCP, Ollama, Jupyter collectors end-to-end to payload, plus the first secret
   detectors (zero-FP corpora).
3. **M2b — Remaining core surfaces:** A2A, vLLM, LiteLLM, Qdrant, MLflow,
   Open WebUI, LangServe.
4. **M2c — Long tail:** generic `OpenAICompatibleEndpoint`, Ray dashboard,
   Langflow, Flowise, ChromaDB.
5. **M2d — Path-qualification rules:** opt-in traversable edges for cases that
   clear the bar (Jupyter auth-disabled leads; Ray, Langflow follow).
   Does not ship if M0 cannot verify rule-enabled traversal.
6. **M3 — Resume + upload:** resume, CE API client, saved queries, adapter
   validation gate.
7. **M4 (future) — Credentials:** authenticated enumeration, access evidence.
8. **M5 (future, secondary) — Library listing:** description docs per node/edge kind,
   submission to `SpecterOps/bloodhound-docs` "Library Change" issue.

## Working conventions

- Repo: `~/Projects/LLMHound`.
- Default branch is `QA`; small committed steps; docs live under `docs/`.
- Discovery ports/paths are data-driven fingerprint definitions (embedded,
  overridable). Baseline: Ollama 11434, vLLM 8000, MLflow 5000, Jupyter 8888,
  Qdrant 6333, Open WebUI 3000/8080, LiteLLM 4000, MCP/A2A on 80/443/8080 +
  well-known paths.
- Design decisions follow the brainstorming-first process: design docs in
  `docs/plans/` before code.
