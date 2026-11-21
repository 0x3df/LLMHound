# Qdrant collector

> **Status: M2b Qdrant collector implemented.** Companion to
> [design](../01-design.md),
> [graph model](../02-graph-model.md), and
> [capability matrix](../03-collector-capabilities.md).
> Implemented in `internal/collectors/qdrant`.

The Qdrant collector performs anonymous, bounded, read-only enumeration of
Qdrant vector database instances (version, commit, collections, schema metadata,
snapshot listings, and optional bounded point payload sampling) without
fetching embedding vectors or mutating collections or snapshots.

## Collection Policy and Safety

- **Read-Only & Anonymous:** No credentials are sent. Metadata checks use HTTP
  `GET` only; snapshot creation (`POST /snapshots`) and collection/point
  mutations are never called.
- **Bounded Content-Tier Sampling (`qdrant_points_sample`):** When
  `content.enabled` and `content.surfaces.qdrant` allow (default `true`), the
  collector issues `POST /collections/<name>/points/scroll` with
  `{"limit": content.max_sample_points, "with_payload": true, "with_vector": false}`.
  Any vector fields are ignored at decode time so embeddings are never kept.
  Non-binary payloads are written within `content.*` limits to
  `<prefix>.content.jsonl` (mode `0600`), scanned by `internal/secrets` (values
  replaced by `[secret:<type>]`, `detected_exposures` recorded in the sidecar,
  and `has_exposed_secret`/`secret_types`/`secret_last_confirmed` surfaced on
  `QdrantInstance`), and excluded from `anon_operations`. Disable with
  `--content=false` or `--content-disable=qdrant`.
- **TLS & Redirects:** TLS verification is enforced by default unless
  `--insecure` is explicitly enabled and recorded; redirects are bounded and
  rechecked per hop.

## Allowlisted Operations

| Check ID | Operation | Endpoint | Method | Purpose | Outcome Semantics |
|---|---|---|---|---|---|
| `qdrant_version` | `qdrant_version` | `/` | `GET` | Qdrant title, runtime version, and commit (excluded from `anon_operations`) | `success`: Qdrant root identified; `denied`: 401/403; `failed`: non-Qdrant JSON, 404, 429, truncated, or transport error |
| `qdrant_collections` | `qdrant_collections` | `/collections` | `GET` | Collection inventory | `success`: collections listed anonymously; `denied`: 401/403; `failed`: 404, 429, malformed, truncated, or transport error |
| `qdrant_collection_info` | `qdrant_collection_info` | `/collections/<name>` | `GET` | Per-collection status, point/vector/segment counts, dimensions, and distance | `success`: metadata retrieved for >=1 collection; `skipped`: collections unavailable or empty; `denied`/`failed`: all refused/errored |
| `qdrant_snapshots` | `qdrant_snapshots` | `/snapshots` | `GET` | Exposed snapshot listing metadata | `success`: snapshot list returned; `denied`: 401/403; `failed`: 404, 429, malformed, or transport error |
| `qdrant_points_sample` | `qdrant_points_sample` | `/collections/<name>/points/scroll` | `POST` | Bounded payload-only sampling into `.content.jsonl` (`with_vector: false`) | `skipped`: disabled by `content.*` policy or no collections; `success`: >=1 collection sampled cleanly; `denied`/`failed`: all refused/errored |

## Graph and Evidence Mapping

- **Nodes:**
  - `QdrantInstance` (with `AIService` umbrella label), carrying the shared
    [service property contract](../02-graph-model.md#property-contract)
    (endpoint, access, `commit`, `collection_count`, content summary, TLS),
    `software_version`, `software_version_raw`, and (when `qdrant_snapshots`
    succeeds) `snapshots_exposed` + `snapshot_count`. `exec_surface` is omitted.
  - `VectorCollection` nodes (bounded by `bounds.max_items`), carrying
    `collection_name`, `status`, `points_count`, `indexed_vectors_count`,
    `segments_count`, `dimensions`, `distance`, and `vector_names` (for
    named-vector collections).
  - Fallback `NetworkEndpoint` when the asset mapping does not name an existing
    BloodHound node for the target.
- **Edges:**
  - `Contains` (`QdrantInstance` → `VectorCollection`).
  - `ObservedAt` (`QdrantInstance` → mapped native node or `NetworkEndpoint`).
- **Evidence sidecar:** `check_result` / access evidence, `fingerprint`, `tls`,
  `redirect`, and `correlation` records.
