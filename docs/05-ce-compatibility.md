# BloodHound CE compatibility (M0)

> **Status: answered against BloodHound CE 9.7.1 (live spike).** Answers below
> were observed on a running pinned lab, not derived from docs. Docs
> (fetched 2026-09-29/30 from bloodhound.specterops.io) informed what to test;
> every answer records the request/response or Cypher evidence that produced
> it. The tier-0 follow-ups R1–R9 were answered the same way on 2026-11-21 (see the last
> section). `extension/schema.json` and the adapter mapping are written from
> these answers, and `llmhound upload` (`internal/bloodhound.Client.ValidateAdapter`) re-checks them.

## Test environment

| Item | Value |
|---|---|
| BloodHound CE version | **v9.7.1** (`GET /api/version`: `server_version: "v9.7.1"`, `product_edition: "community"`) |
| CE image digest | `specterops/bloodhound@sha256:33ec454115f304952236a5a9716e78a734a6a13f9e8ec2bacc823a423f586331` (tag `9.7.1`; note: image tags have **no `v` prefix**, GitHub release tags do) |
| PostgreSQL version | 18.6 (`postgres (PostgreSQL) 18.6 (Debian 18.6-1.pgdg13+2)`), image `postgres@sha256:5a5a84b19854a9ffaa54082c166ff4ec27473a361e496e5ea167f298f2da9722` |
| Graph driver | `pg` (PostgreSQL app-db serves as graph database; Neo4j unused) |
| OpenGraph schema version | API v2 (`API.current_version: "v2"`); extension definition schema format per the 9.x developer docs |
| Date tested | 2026-09-29/30 |
| Harness | `lab/` in this repo: docker-compose CE + PostgreSQL (loopback only, dedicated Compose project), toy extension `lab/fixtures/extension/llmhound-m0-schema.json`, toy payloads, synthetic SharpHound v6 AD fixture (`LAB.LOCAL`, Computers `-1103`/`-1104`). Reproduce with `lab/scripts/lab-up.sh`, `lab/scripts/run-m0-checks.sh` (evidence per check in `lab/.runtime/results/m0-checks.jsonl`); see `lab/README.md`. |

Unless noted, every "rejected/accepted" below is the observed HTTP status of
the corresponding API call or the recorded per-file ingest task status.

## Questions

### Q1 — Are node/edge kinds namespaced per extension, or global? Collision behavior?

**Answer: kinds are globally unique strings, namespaced by a mandatory
`<namespace>_` prefix; collisions and unprefixed names are hard-rejected at
extension registration (HTTP 400).**

Observed on `PUT /api/v2/extensions`:

- Unprefixed node kind `OllamaInstance` → `400`: *"graph schema node kind
  OllamaInstance is missing extension namespace prefix"*.
- Node kind exactly `Computer` (built-in) → `400`: same
  "missing extension namespace prefix" message.
- Edge kind exactly `MemberOf` (built-in) → `400`: same.
- A second extension (`ToySpikeCollide`, distinct `schema.name`) reusing the
  namespace `ToySpike` of an installed extension → `400`:
  *"duplicate graph schema extension namespace: ToySpike"*. **Extension
  namespaces are globally unique and exclusive.**
- Two distinct extensions with distinct namespaces coexist fine
  (`LLMHound` + `ToySpike` both installed, `GET /api/v2/extensions` lists both).
- Re-registering the same `schema.name` with a changed
  version/display_name → `200` (upsert/overwrite works; version `v0.0.2` was
  accepted after `v0.0.1`).
- The `tag` prefix is rejected in any letter case for custom kinds (docs;
  not re-tested — the namespace rule already forces prefixed names).

**Consequence for LLMHound:** the "clean logical names" in the graph model
are emitted as `LLMHound_<Kind>` (e.g. logical `OllamaInstance` → emitted
`LLMHound_OllamaInstance`) with `display_name` carrying the clean label
("Ollama Instance"). The namespace is `LLMHound` — owned exclusively by this
extension, so no other extension can take those kind strings. Cleanup uses
the `LLMHound` source kind, never a name-prefix convention. The
logical→emitted mapping is defined centrally in the adapter (M1) and used
consistently in schema, payloads, and saved queries. Saved queries must
match `LLMHound_*` kinds, not bare logical names.

### Q2 — Can a node carry an extra label (`AIService`) in addition to its primary kind, and is it queryable?

**Answer: yes. All values in `kinds` become queryable labels; `AIService`
works as an umbrella label when defined in the extension schema.**

Observed:

- Payload nodes with `kinds: ["LLMHound_OllamaInstance", "LLMHound_AIService"]`
  ingest fine; Cypher `MATCH (n:LLMHound_AIService) RETURN n` returns both
  service nodes with kinds `["LLMHound_OllamaInstance", "LLMHound_AIService",
  "LLMHound"]` — note CE also appends the `source_kind` (`LLMHound`) as an
  extra label on every node of a payload that declares it in `metadata`.
- Up to three kinds per node is the payload schema limit (docs; our payloads
  use ≤ 3 and were accepted).
- An **unprefixed** extra label (`kinds: [..., "AIService"]` without a
  matching `node_kinds.name` entry) was also accepted at ingest and persists
  as a queryable label — but it is not part of the structured schema. LLMHound
  will not rely on that: the umbrella label is declared as
  `LLMHound_AIService` in the extension schema (Q1's namespace rule requires
  the prefix anyway for structured-graph kinds).

**Consequence:** `AIService` ships as a real node kind in the schema and is
used as the second kind on every concrete AI-service node; saved queries
filter on it. `source_kind` labels (`LLMHound`) appear on ingested nodes
automatically and are not used for kind-based querying.

### Q3 — Which property types are accepted? Size limits?

**Answer: string, number (int/float), boolean, and homogeneous arrays of
those are accepted and preserved. Nested objects, arrays of objects, and
heterogeneous arrays are rejected at upload (HTTP 400 with per-property
schema-validation messages). Property names are case-sensitive; several
string values and node ids are upper-cased during ingest.**

Observed:

- `prop_string`/`prop_int` (42)/`prop_float` (4.2)/`prop_bool`/empty string,
  arrays of strings/numbers/bools: accepted; values read back through Cypher
  unchanged, arrays returned as arrays.
- `prop_nested: {a: 1}` → `400` at upload: *"nodes[0] schema validation
  failed … at '/properties/prop_nested': got object, want string"*. Payloads
  are validated synchronously at upload — **invalid payloads never enter the
  ingest queue**.
- Array of objects → `400` (same validation path).
- Heterogeneous array `["a", 1, true]` → `400`.
- `properties.objectid` → `400`: *"at '/properties': 'not' failed"*
  (reserved property enforced).
- Node kind `tag_probe_kind` → `400`: *"kind 'tag_probe_kind' uses reserved
  namespace prefix"* (whole upload rejected).
- Property names are case-sensitive: `PropertyName` and `propertyname` on one
  node remain two distinct properties.
- Uppercasing at ingest (confirmed by read-back): node **ids** (`m0-upsert-1`
  stored as `M0-UPSERT-1`, property `objectid` upper-cased too), and the
  string property values of `name`, `operatingsystem`, `distinguishedname`.
- `lastseen` is injected automatically (overwrites any payload value);
  `primarykind` is recorded from the first `kinds` entry.
- Size limits: not bounded during the spike; ~1 MB (4k nodes, 61 s wall time)
  and ~10 MB (40k nodes, 60 s) payloads ingested without errors. Neither CE
  nor the upload API imposed a rejection in this range. LLMHound still pages
  payloads; untested: behavior at ≥100 MB.

**Consequence:** graph properties stay flat and primitive (as the graph model
requires); anything nested goes to the `.evidence.jsonl` sidecar referenced
by stable evidence IDs. Property names are emitted lowercase to avoid the
case-sensitivity trap. **All emitted node ids must be case-normalized** — CE
upper-cases them anyway, so LLMHound matches/upserts by the upper-cased form
(our SHA-256 hex ids are already case-insensitive-safe, but any mixed-case
id would be silently mutated). Never emit values into `name` that must keep
their case (they will be upper-cased).

### Q4 — How is an edge kind declared non-traversable, and do pathfinding and the UI honor it?

**Answer: `is_traversable: false` in the extension schema's
`relationship_kinds` entry. Pathfinding honors it.**

Observed via `GET /api/v2/graphs/shortest-path`:

- Chain of two non-traversable `LLMHound_ObservedAt` edges, request with
  `only_traversable=true` → **HTTP 404 `"path not found"`** (non-traversable
  edges excluded from pathfinding).
- Same graph, `only_traversable=true`, where a route using only the
  traversable control edge exists → path returned containing **only**
  `LLMHound_M0TraversableControl` edges — the engine routed around the
  non-traversable chain.
- Same pair without the flag → path returned including the
  non-traversable edge kinds (raw search finds everything).
- `relationship_kinds` filter format is `in|nin:Kind1,Kind2` (a bare kind
  list is rejected with `400` documenting the format). Filtering explicitly
  to extension kinds returned empty results in our probes — the probes ran
  after the nodes had been cleaned up, so this sub-behavior is
  **unverified**; do not rely on `relationship_kinds` filtering for
  extension kinds until retested.
- Generic-graph edges (no extension schema) are treated as non-traversable
  per docs; all LLMHound edges are declared in the schema with
  `is_traversable: false` explicitly, so traversal behavior does not depend
  on the generic path.

**Consequence:** every LLMHound relationship kind is registered with
`is_traversable: false`; access-evidence edges and topology edges are equally
non-traversable, and pathfinding demonstrably honors it. The UI/API
shortest-path endpoint returns "path not found" (404) rather than an empty
graph when only non-traversable edges connect two nodes — clients must treat
404 here as "no traversable path", not as an error.

### Q5 — Does `source_kind` cleanup remove only LLMHound-sourced nodes and edges? What happens to LLMHound edges that touch native `Computer` nodes?

**Answer: cleanup is scoped to the source kind, BUT a payload that declares
`metadata.source_kind` tags EVERY node it touches — including existing AD
`Computer` nodes referenced as edge endpoints — and source deletion then
deletes those Computers. The two-step upload workaround prevents this.**

Observed (all reproduced live on v9.7.1):

- Hybrid payload ( declares `metadata.source_kind: "LLMHound"` and links a
  LLMHound node to existing Computer `-1103` by objectid): after ingest the
  Computer's kinds became `["Base", "Computer", "LLMHound"]` — **the
  collector's source_kind label is applied to referenced AD nodes** (this is
  the OpenGraph FAQ's documented pitfall, confirmed real on 9.7.1).
- `POST /api/v2/clear-database` with `{"deleteSourceKinds": [<LLMHound id>]}`
  → `204`; effects settle asynchronously (~1 minute). It deleted: every node
  tagged `LLMHound` **including the referenced Computer `-1103`**, LLMHound
  edges, and the `LLMHound` record from the source-kinds table. Control
  Computers never referenced by a `source_kind` payload (`-1104`) and other
  AD nodes survived.
- Two-step workaround verified end-to-end: (1) upload the LLMHound-owned
  subgraph **with** `metadata.source_kind`; (2) upload linking edges to
  Computers **without** `metadata.source_kind` — the Computer stays
  untagged; a later source deletion removed the LLMHound nodes but the
  Computer survived.
- Cleanup is asynchronous; the source record disappears from the source
  table within ~1 minute.
- Caveat discovered: an edge endpoint `match_by id` referencing a **missing**
  node does not fail — ingest **materializes an empty stub node** (no kinds,
  label = objectid) and attaches the edge to it. Correlation code must
  verify endpoint existence (mapping file / CE API lookup) before emitting
  linking edges.

**Consequence (design-relevant):** LLMHound's upload pipeline must be
two-step per scan: payload 1 = all LLMHound-owned nodes/edges (source_kind
declared, no AD endpoints); payload 2+ = linking/correlation edges to
existing `Computer` nodes with **no** `metadata.source_kind`. Source-scoped
cleanup then removes only LLMHound's own nodes; native Computers survive.
Linking edges and sourceless linking nodes are NOT removed by source cleanup
(they become sourceless data — deletable via the "Sourceless" cleanup
option). The API endpoint for sources on this build is
`GET /api/v2/graphs/source-kinds` (hyphenated; the docs' `/source_kinds`
path returns 404), shape `{data: {kinds: [{id, name}]}}`;
`deleteSourceKinds` takes those integer ids.

### Q6 — Can an edge endpoint reference an existing node by property match? Case-sensitivity? Zero/multiple matches?

**Answer: yes — `match_by: "property"` with `property_matchers`
(`operator: "equals"` only) and an optional `kind` filter. Matching is
case-sensitive against the stored (upper-cased) values. Zero and multiple
matches both drop the edge silently (upload still accepted, no per-file
errors).**

Observed against SharpHound-ingested Computers:

- `name` = `LAB-WIN-01.LAB.LOCAL` (exact upper-case) with `kind: Computer` →
  edge created to that Computer (single match as expected).
- `name` = `lab-win-01.lab.local` (lower-case) → **no edge** (stored values
  are upper-cased at ingest; matching is case-sensitive).
- `name` = `NO-SUCH-HOST.LAB.LOCAL` (zero matches) → **no edge**, no error,
  upload accepted with no per-file errors.
- `domain` = `LAB.LOCAL` (matches BOTH Computers) → **no edge** to either —
  ambiguous matches drop the edge silently rather than fanning out or
  erroring.
- `samaccountname` = `LAB-WIN-02$` (not in the uppercased list) exact → edge
  created.

**Consequence for correlation rule 2 (historical — retired AD-suffix matching; superseded by mapping-file-only attachment):** CE's property match
is usable for correlation only with exact, correctly-cased match values.
Because ingest upper-cases `name`, the collector must emit the upper-cased
FQDN in the matcher. Silent edge-dropping on zero/ambiguous matches means
LLMHound cannot rely on CE to reject ambiguous correlation — the collector
resolves ambiguity itself (mapping file precedence, CE API lookup, explicit
`NetworkEndpoint` fallback) and only emits endpoints it has verified.
Correlation `match_method`/`match_value`/`confidence` stay in edge
properties + evidence regardless.

### Q7 — Does an edge to an existing `Computer` by objectid resolve when the Computer was ingested by SharpHound?

**Answer: yes.** `match_by: "id"` with the Computer's SID (the same
identifier SharpHound ingested as its objectid) resolves the edge to the
existing AD Computer node — verified by re-querying
`MATCH (s)-[r:LLMHound_ObservedAt]->(c:Computer)` and observing
`c.objectid = S-1-5-21-…-1104`, with the edge carrying our
`match_method`/`match_value`/`confidence` properties. No new Computer node
was created; no native identifier was touched.

**Consequence (historical note — runtime CE lookup retired in favor of mapping-file attachment + pre-flight):** correlation rule 1 (mapping file)
emits `ObservedAt` edges with `match_by: id` on the native node ID. This is the
preferred, exact matching path (CE docs also recommend id matching over
property matching).

### Q8 — Upsert behavior: update or duplicate? Are stale properties removed?

**Answer: upsert by node id — no duplicates; properties MERGE; stale
properties are NOT removed; `lastseen` refreshes. Edges upsert too
(identical kind/start/end does not duplicate).**

Observed:

- Upload node `M0-UPSERT-1` (props `description: v1`, `keep_prop`, 
  `stale_prop`) → then re-upload same id with `description: v2` and
  `stale_prop` omitted: node count stays **1** (no duplicate);
  `description` updated to `v2`; `stale_prop` still present; `keep_prop`
  intact; `lastseen` refreshed.
- A node present in upload 1 but omitted from upload 2 **remains** in the
  graph (absence is not deletion — matches the design's lifecycle contract).
- Re-uploading an identical edge (same kind/start/end) does not duplicate
  it (edge count stays 1). Edge properties presumably merge the same way
  (not separately verified).

**Consequence:** repeated LLMHound scans upsert cleanly (stable identity),
but stale properties (e.g. an old `coverage` value) are never automatically
removed by CE — the ingest lifecycle must handle stale values itself (the
graph model already assigns this to an explicit reconciliation policy, and
freshness/expiry remains LLMHound's responsibility, not CE's).

### Q9 — Saved-query import format and API

**Answer: yes.** `POST /api/v2/saved-queries` accepts
`{name, query, description}` (JSON) → `201`. `POST /api/v2/saved-queries/import`
accepts either a JSON file or a ZIP of such JSON files (the Query Library
export format) → `201` with `{"data": "imported 2 queries"}`;
`GET /api/v2/saved-queries` lists them afterwards.

**Consequence:** starter saved queries ship as `{name, query, description}`
JSONs (zipped) and are imported via `/api/v2/saved-queries/import` (the
design's `POST /api/v2/saved-queries` shorthand for single queries also
holds). Queries must use the emitted `LLMHound_*` kinds and flat properties
per Q1/Q3.

### Q10 — Payload size limits and ZIP upload handling

**Answer: JSON and ZIP both accepted via the job-based upload API
(`POST /api/v2/file-upload/start` → `POST /api/v2/file-upload/{id}` with
`Content-Type` + optional `X-File-Upload-Name` header →
`POST /api/v2/file-upload/{id}/end`). ZIP may contain multiple payload
files (all ingested). Nested ZIPs produce a per-file error
(`"file is not valid json"`), not a global failure — other files in the same
job still ingest. ~1 MB and ~10 MB payloads ingested without rejection
(61 s / 60 s wall time). Upload-jobs listing shape:
`GET /api/v2/file-upload` (jobs with integer `status`); per-file results:
`GET /api/v2/file-upload/{id}/completed-tasks`.**

**Consequence:** large scans can be emitted as multi-file ZIPs; LLMHound
checks per-file task results rather than relying on job status alone.

**Not measured:** pagination defaults of `GET /api/v2/file-upload` and
`GET /api/v2/saved-queries`. The client therefore never assumes a job or query
is on the first page: it looks a job up with `?id=eq:<id>` and, if CE rejects
or ignores the filter, pages with `skip`/`limit` (bounded, stopping when rows
repeat); a job absent from the listing is never treated as complete. Confirming
the filter in the lab is backlog item [F1](06-roadmap.md#development-backlog-in-order); repeat
it (`run-m3-gate.sh`) whenever the pinned CE version changes.
Note the docs' `POST /api/v2/file-upload` description in the design doc is
the older single-step form; on 9.7.1 the flow above is what actually works.

## Decisions recorded

1. **Kind mapping (logical → emitted):** every kind is emitted with the
   `LLMHound_` namespace prefix (e.g. `OllamaInstance` →
   `LLMHound_OllamaInstance`, `ObservedAt` → `LLMHound_ObservedAt`);
   `display_name` carries the clean label. `AIService` umbrella label is
   emitted as `LLMHound_AIService` and attached as the second kind of
   concrete service nodes. Source kind stays `LLMHound` (CE appends it
   automatically to payload nodes). Central definition lives in the M1
   adapter; schema, payloads, and saved queries all use emitted names.
2. **Property serialization:** flat primitives or homogeneous primitive
   arrays only; lowercase property names; values that must preserve case
   (hostnames, digests, paths) must NOT be placed in `name` — use dedicated
   lowercase-named properties (e.g. `endpoint_host`); node ids treated as
   case-insensitive (CE upper-cases them).
3. **Correlation rules actually supported on v9.7.1:**
   - Rule 1 (mapping file → Computer objectid/SID): emit `ObservedAt` with
     `match_by: id`. Verified working (Q7).
   - Rule 2 (AD-suffix FQDN → property match): emit `match_by: property`
     with `property_matchers` on `name` **upper-cased**, `kind: Computer`.
     Works only for exact single matches (Q6): the collector must resolve
     ambiguity and existence itself; zero/ambiguous matches fall back to
     `NetworkEndpoint` (CE drops such edges silently).
     **Superseded:** LLMHound no longer emits property matches. Attribution
     belongs to the normalizer and every attachment is an objectid match
     (see [02-graph-model.md](02-graph-model.md#attachment-to-existing-nodes)).
     This item records what CE supports, not what LLMHound does.
   - Endpoint existence must be verified before emission — missing endpoints
     materialize empty kindless stub nodes (Q5 caveat).
4. **Upload pipeline (per scan):** two-step — (1) LLMHound-owned subgraph
   with `metadata.source_kind: "LLMHound"`; (2) linking/correlation payloads
   **without** `metadata.source_kind`. Never declare `source_kind` on a
   payload that touches AD nodes (Q5: Computers would be tagged and later
   deleted with the source). Cleanup via
   `POST /api/v2/clear-database {deleteSourceKinds: [<LLMHound id>]}` where
   the id comes from `GET /api/v2/graphs/source-kinds`; deletion is
   asynchronous (~1 min) and its completion must be awaited/verified.
5. **Non-traversable edges:** every LLMHound relationship kind is registered
   with `is_traversable: false` (Q4). No LLMHound edge is traversable by default.
   *(Updated 2026-11-21: opt-in path-qualification rules in M2d may register
   `LLMHound_CanExecuteOn` as traversable, verified at the API level by R5 below.)*
6. **Adapter honesty notes (observed CE behaviors that affect clients):**
   - `GET /api/v2/graphs/source_kinds` (docs) → 404; use
     `GET /api/v2/graphs/source-kinds` (hyphen), shape `{data:{kinds:[…]}}`.
   - Upload job statuses observed: `0` ready, `1` running, `2` complete,
     `3` canceled, `8` partially completed/per-file failures — treat `8` as
     terminal and inspect `completed-tasks`.
   - `/api/v2/file-upload/{id}/end` returns `200` (docs say 202).
   - Cypher queries that probe a node by `objectid` equality return
     **HTTP 404 "resource not found" when nothing matches** (not an empty
     result set); relationship-pattern queries that match no edges also
     return 404. Treat 404 on such probes as "zero rows".
   - `shortest-path` returns an empty graph (HTTP 200) for unknown
     start/end ids — id validation is the caller's job.
   - Ingest is asynchronous with variable latency (~1 s idle → ~1 min for
     larger batches); uploads must poll jobs and verify per-file tasks.
7. **Validated combination:** CE 9.7.1 + PostgreSQL 18.6 + `graph_driver=pg`.
   Re-run `lab/scripts/run-m0-checks.sh`, `lab/scripts/run-r-checks.sh`, and
   `lab/scripts/run-m3-gate.sh` against any candidate CE release before
   declaring support; `llmhound upload` rejects unpinned CE versions unless
   `--allow-unvalidated-ce` is passed.

## Unverified / open (not blocking M1)

- Payload rejection thresholds ≥ ~100 MB and ZIP size limits (spike tested
  up to ~10 MB).
- UI rendering of a traversable extension edge (R5 verified the API only).
- Behavior of the unscoped sourceless sweep (`deleteSourceKinds: [0]`) on stub nodes (R8).
- Entity-panel `info` markdown rendering and custom icons (schema accepted;
  not UI-verified — cosmetic, not needed for M1 emission).
- Neo4j-driver behavior is out of scope (LLMHound targets PostgreSQL-backed
  CE only).

## Follow-up answers for the tier-0 redesign (R1–R9)

The 2026-11-20 redesign (see [graph model](02-graph-model.md)) depended on behaviors M0
did not test. All nine were answered on the pinned lab on 2026-11-21 by
`lab/scripts/run-r-checks.sh`, which registers the **real** `extension/schema.json` (plus
one traversable `LLMHound_CanExecuteOn` kind, to test rule edges), ingests a synthetic
SharpHound attack-path scenario (`lab/fixtures/ad/paths`: Domain Users has `GenericAll`
over a Computer where a tier-0 account has a session) and an AzureHound-format VM
(`lab/fixtures/azure`), then uploads realistic LLMHound payloads. Evidence is one JSON
line per check in `lab/.runtime/results/r-checks.jsonl`. M0's answers above still hold:
arrays of primitives are accepted (Q3), `is_traversable: false` is honored by pathfinding
while raw search still finds the edges (Q4), and property matching silently drops zero or
ambiguous matches (Q6).

| # | Question | Answer | Consequence |
|---|---|---|---|
| R1 | How are tier-0 nodes tagged? | **Closed.** A node is tier 0 when it carries the label `Tag_Tier_Zero`. It also has the **string** property `system_tags = 'admin_tier_0'`. The documented array form `'admin_tier_0' IN n.system_tags` fails with HTTP 500 (`cannot extract elements from a scalar`). `n:Tag_Tier_Zero`, `n.system_tags = 'admin_tier_0'` and `CONTAINS` all work. CE's own list: `GET /api/v2/asset-group-tags` (Tier Zero id 1, Owned id 2) and `/asset-group-tags/1/members`. The fixture's tier-0 set was the Domain, Domain Admins and one admin user. Membership is computed by analysis after ingest, so wait for `datapipe/status` to be `idle`. | Saved queries use `Tag_Tier_Zero`. |
| R2 | Do typed-kind `shortestPath` queries work and scale? | **Closed, with shape rules.** Typed (`[:A\|B*1..]`) and untyped (`[*1..]`) shortest paths both run; the typed ones took under 100 ms on a graph with 3,000 services attached to one Computer, including a pattern with all 107 traversable kinds from `extensions-edges`. Raw Cypher follows every edge kind, so typed lists are still required (below). Shape limits on 9.7.1/PostgreSQL: (a) `shortestPath` endpoints must be declared inline in the pattern with the filter in a trailing `WHERE`; endpoints bound by an earlier `MATCH` fail with HTTP 500 (`relation "s0" does not exist`). (b) A path to hosts that have a service is expressed with a pattern predicate in that `WHERE`: `AND (h)<-[:LLMHound_ObservedAt]-(:LLMHound_AIService)`. `EXISTS((...))` does not parse. (c) `length(p)` is unknown, and `ORDER BY size(relationships(p))` fails, so results cannot be ranked by path length. (d) A join followed by a **bounded** variable-length pattern (`*1..4`, not `shortestPath`) works and carries the service in the result. (e) An unbounded result is capped near 1,000 nodes (1,002 returned for 3,003 services), so queries must `LIMIT`. (f) A shared `AIService` label, array predicates (`any(x IN ...)`, `'x' IN s.anon_operations`) and `OPTIONAL MATCH` all work. | [04](04-saved-queries.md) is rewritten to these shapes; the path-ranking questions use the shortest-path API. |
| R3 | Does `match_by: id` resolve AzureHound nodes? | **Closed.** An `AZVM` is stored with `objectid` = the full **upper-cased ARM resource ID** (`/SUBSCRIPTIONS/.../VIRTUALMACHINES/NAME`). An edge to that id resolves to the existing `AZVM`. A lower-cased ARM id also resolves (CE upper-cases match values). The VM's GUID (`vmId`) does **not** resolve: CE created a kindless stub. | An Azure mapping entry's `object_id` must be the ARM resource ID, never the VM GUID. Documented in [02](02-graph-model.md#attachment-to-existing-nodes). |
| R4 | Are arrays replaced or merged on re-upload? Do edge properties update? | **Closed.** Arrays are **replaced wholesale** (a shorter array replaces a longer one; nothing stale remains) and stored **verbatim** (duplicates and order are kept). A re-uploaded edge stays one edge and its changed property updates; CE adds `lastseen`. | `anon_operations`, `exec_surface`, `secret_types` are safe to re-emit each scan. Emit them sorted and de-duplicated. |
| R5 | Is a traversable extension edge honored by pathfinding? | **Closed (API).** With `only_traversable=true`, no path existed from a service to Domain Admins until a sourceless `LLMHound_CanExecuteOn` edge (service → Computer) was added; then the API returned service → Computer → tier-0 user → Domain Admins using `CanExecuteOn`, `HasSession`, `MemberOf`. The non-traversable `ObservedAt` is only followed when the filter is off. Edge direction matters (a path Computer → service does not exist). UI rendering was not checked. | Path-qualification rules (D7) are viable as designed. |
| R6 | Does a stale `true` persist, and what is the refresh pattern? | **Closed.** A later payload that omits `has_exposed_secret` and `secret_types` leaves both set (`true` persists). An explicit `false` overwrites, but asserting absence violates the precision rule. A `null` value is rejected by CE at upload. A string comparison on an ISO-8601 timestamp works in Cypher. | `has_exposed_secret` stays true-or-unset; every query reads it with `secret_last_confirmed >= <cutoff>` (see [02](02-graph-model.md#property-contract)). |
| R7 | What is the cheapest read-only pre-flight call? | **Closed.** One `POST /api/v2/graphs/cypher` call with `MATCH (n) WHERE n.objectid IN [...] RETURN n` (ids upper-cased) returns every id that exists with its `kinds`; a 501-id list took 66 ms. A stub from a bad edge has `kinds: []` and only `objectid` and `lastseen`, so **an id exists only if the returned node has at least one kind**. A query matching nothing returns HTTP 404, which is "zero rows". Lists are capped by the ~1,000-node result limit, so check in chunks of 500. | `upload` (D8) uses this call; stubs already in a graph are found with `MATCH (n) WHERE size(labels(n)) = 0 RETURN n`. |
| R8 | What does cleanup remove? | **Closed.** `clear-database` with `deleteRelationships: ["LLMHound_ObservedAt"]` returns 204 and removes every edge of that kind (sourced and sourceless) **asynchronously**, leaving all nodes. `deleteSourceKinds: [<LLMHound id>]` after the two-step load removes the LLMHound nodes and the attachment edges and leaves native nodes intact; native count was unchanged. `deleteSourceKinds: [0]` (sourceless nodes) left native AD nodes and LLMHound nodes untouched in this lab, but its scope is not documented: do not use it. A kindless stub created by an edge to a missing endpoint is not owned by any source and survives source cleanup (seen in an earlier pass), which is why the pre-flight (R7) matters. | The normalizer cleans up with the source-kind delete or per-kind `deleteRelationships`; both must be polled to completion. |
| R9 | Does `relationship_kinds` work with extension kinds? | **Closed.** `relationship_kinds=in:MemberOf,GenericAll,HasSession` and `nin:GenericAll` filter native-kind paths as expected (the `nin` case correctly found no path). `in:LLMHound_CanExecuteOn,HasSession,MemberOf` works with an extension kind. An unknown kind returns HTTP 400 (`invalid query parameter`). | Optional UI/API path filters are supported. |

### Other behavior found while running R1–R9

- **`GET /api/v2/extensions-edges` ignores its query parameters.** `is_traversable` and
  `schemas` have no effect: it always returns all 148 kinds (107 traversable on the lab:
  built-in AD/Azure plus extensions), each as `{name, is_traversable, schema_name,
  is_builtin}`. Filter client-side. This is the authoritative source for generated
  `PATH_KINDS`. `LLMHound_CanExecuteOn` is the only extension kind reported traversable.
- **Ingest is slow and not always reliable right after a reset.** An upload started
  while the pipeline is still settling after `clear-database` can end in job status `3`
  (canceled) and a job can sit in status `6` (ingesting) with an idle pipeline. 3,000
  sourceless edges onto one Computer took 60 s in one run and 320 s in another.
  `internal/bloodhound` polls with a timeout, inspects per-file completed tasks,
  and retries canceled jobs.
- **Saved-query import rejects duplicate names** (HTTP 400, `duplicate name for saved query`),
  and a graph reset does not remove saved queries. An installer deletes prior `LLMHound*`
  queries first.
- **Aggregates return no nodes.** `RETURN count(s)` yields a successful response with zero
  nodes, so counts must be read from the response data, not the node map.

