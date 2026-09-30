# BloodHound CE compatibility (M0)

> **Status: open questions.** M0 fills this in. Nothing below is answered
> yet. M1's `extension/schema.json` and the graph model's adapter mapping are
> written from these answers, and M3's adapter validation gate re-checks them.

## Test environment

| Item | Value |
|---|---|
| CE version / image digest | _TBD (pin exactly)_ |
| PostgreSQL version | _TBD_ |
| OpenGraph schema version | _TBD_ |
| Date tested | _TBD_ |
| Harness | docker-compose CE + PostgreSQL; toy extension + toy payload |

## Questions

Record each answer with the evidence you observed: a request/response, a Cypher
result, or a UI screenshot. Also record its consequence for LLMHound.

| # | Question | Why it matters | Answer | Consequence |
|---|---|---|---|---|
| 1 | Are node/edge kinds namespaced per extension, or global? Does registering a kind another extension already defines fail, merge, or shadow? | Decides clean names vs. a prefix ([naming contract](graph-model.md#naming-contract)) | | |
| 2 | Can a node carry an extra label (`AIService`) in addition to its primary kind, and is it queryable? | Umbrella label and saved queries | | |
| 3 | Which property types are accepted (string, number, bool, arrays, nested objects)? Are there size limits? | Flat property layout vs. evidence sidecar | | |
| 4 | How is an edge kind declared non-traversable, and do pathfinding and the UI honor it? | Every v1 edge is non-traversable | | |
| 5 | Does `source_kind` cleanup remove only LLMHound-sourced nodes and edges? What happens to LLMHound edges that touch native `Computer` nodes? | Clean removal must never touch AD data | | |
| 6 | Can an edge endpoint reference an **existing** node by property match (e.g. `match_by` on `Computer` `name`) instead of by objectid? Is the match case-sensitive? What happens with zero or multiple matches? | Correlation rule 2 ([Computer correlation](graph-model.md#computer-correlation)) | | |
| 7 | Does an edge to an existing `Computer` by objectid resolve when the Computer was ingested by SharpHound? | Correlation rules 1 and 3 | | |
| 8 | Upsert behavior: does re-uploading the same objectid update properties or duplicate the node? Are stale properties removed? | Rescans and lifecycle | | |
| 9 | Saved-query import format and API: does `POST /api/v2/saved-queries` accept the Query Library format as-is? | Starter queries | | |
| 10 | Payload size limits and ZIP upload handling | Large scans | | |

## Decisions recorded

_Fill in after M0: the final kind-name mapping (logical → emitted), the
property serialization rules, and the correlation rules that are actually
supported._
