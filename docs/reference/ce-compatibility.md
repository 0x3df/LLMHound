# BloodHound CE compatibility (M0)

> **Status: open questions.** M0 fills this in, and it runs **before** further
> model design: the [graph model](graph-model.md) is a draft until these are
> answered. M1's `extension/schema.json` is written from the answers, and M3's
> adapter validation gate re-checks them.

## Test environment

| Item | Value |
|---|---|
| CE version / image digest | _TBD (pin exactly)_ |
| PostgreSQL version | _TBD_ |
| OpenGraph schema version | _TBD_ |
| Date tested | _TBD_ |
| Harness | docker-compose CE + PostgreSQL; SharpHound sample data (AD Computers, tier-0 tags) plus an AzureHound sample; toy extension and toy payload |

## Questions

Record each answer with the evidence you observed: a request/response, a Cypher
result, or a UI screenshot. Also record its consequence for LLMHound.

| # | Question | Why it matters | Answer | Consequence |
|---|---|---|---|---|
| 1 | Are node/edge kinds namespaced per extension, or global? Does registering a kind another extension already defines fail, merge, or shadow? | Clean names vs. a prefix ([naming contract](graph-model.md#naming-contract)) | | |
| 2 | Can a node carry an extra label (`AIService`) in addition to its primary kind, and is it queryable? | Umbrella label. If not, saved queries use explicit kind lists | | |
| 3 | Which property types are accepted (string, number, bool, arrays of strings, nested objects)? Are `IN` / `any()` over array properties queryable in Cypher? Size limits? | The [property contract](graph-model.md#property-contract) relies on string arrays (`anon_operations`, `exec_surface`, `capability_hint`) | | |
| 4 | How is an edge kind declared non-traversable (and traversable, for rules)? Does built-in pathfinding honor it? Does raw Cypher `shortestPath` honor it or traverse every kind? | Default non-traversable; [path qualification](graph-model.md#path-qualification-traversable-edges) rules need a working traversable class | | |
| 5 | Does a payload edge to an existing node resolve by `objectid` for nodes ingested by SharpHound (`Computer`) and AzureHound (`AZVM`, devices)? Is the lookup scoped by kind? | Attachment by mapping file for any node kind | | |
| 6 | What happens when an edge references an objectid absent from both the payload and the graph? Silent drop, error, or placeholder node? Is it reported in the ingest result? | An attachment to a missing node must not silently orphan a service; decides pre-flight checks | | |
| 7 | Does `source_kind` tagging apply automatically from payload metadata? Can LLMHound-sourced edges that touch native nodes be removed without modifying native nodes? | Provenance and the normalizer's cleanup | | |
| 8 | Upsert behavior: does re-uploading the same objectid update properties or duplicate the node? Are stale properties removed? Are array properties replaced or merged? | Rescans and the normalizer's reconciliation | | |
| 9 | Tier-0 semantics: how are tier-0 nodes tagged (`system_tags` / `admin_tier_0`)? Can Cypher filter on the tag? | Queries P1–P3 | | |
| 10 | Saved-query import: does `POST /api/v2/saved-queries` accept the Query Library format as-is? | Starter queries | | |
| 11 | Performance: do P1/P2-style `shortestPath` queries with an explicit edge-kind list run acceptably on a realistic-size graph? Is there a result or depth limit? | Headline queries | | |
| 12 | Payload size limits and ZIP upload handling | Large scans | | |

## Decisions recorded

_Fill in after M0: the final kind-name mapping (logical → emitted), the property
serialization rules (especially arrays), the supported attachment behavior, and
whether path-qualification rules can ship._
