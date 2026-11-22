# ChromaDB collector

> **Status: Implemented — anonymous, read-only, bounded.** Companion to
> [design](../01-design.md),
> [graph model](../02-graph-model.md), and
> [capability matrix](../03-collector-capabilities.md).
> Implemented in `internal/collectors/chromadb`.

The ChromaDB collector performs anonymous, bounded, read-only enumeration of
ChromaDB vector stores (v2 and legacy v1 APIs: heartbeat, version, auth
identity, collections, item counts, and bounded document/metadata samples)
without ever fetching embeddings.

## Collection Policy and Safety

- **Read-Only & Anonymous:** No credentials are sent. Collection creation,
  upsert, and delete routes are never called.
- **No Embeddings (`chromadb_documents_sample`):** When `content.enabled` and
  `content.surfaces.chromadb` allow (default `true`), bounded sampling sends
  `POST .../collections/<id>/get` with
  `{"limit": content.max_sample_points, "include": ["documents", "metadatas"]}`
  and explicitly excludes `"embeddings"`. Any embedding fields are ignored at
  decode time. Non-binary samples go to `<prefix>.content.jsonl` (mode `0600`)
  through `internal/secrets`.
- **TLS & Redirects:** TLS verification is enforced by default unless
  `--insecure` is explicitly enabled and recorded.

## Allowlisted Operations

| Check ID | Operation | Endpoint | Method | Purpose | Outcome Semantics |
|---|---|---|---|---|---|
| `chromadb_version` | `chromadb_version` | `/api/v{2,1}/heartbeat`, `/api/v{2,1}/version` | `GET` | ChromaDB heartbeat and software/API version (excluded from `anon_operations`) | `success`: heartbeat confirmed; `denied`: 401/403; `failed`: non-Chroma response or transport error |
| `chromadb_auth_identity` | `chromadb_auth_identity` | `/api/v2/auth/identity` | `GET` | Anonymous tenant and database discovery (v2) | `success`: identity retrieved; `unsupported`: v1 API; `denied`/`failed`: refused or errored |
| `chromadb_collections` | `chromadb_collections` | `/api/v2/tenants/<t>/databases/<db>/collections` or `/api/v1/collections` | `GET` | Collection inventory | `success`: collections enumerated anonymously; `denied`: 401/403; `failed`: malformed or transport error |
| `chromadb_collection_count` | `chromadb_collection_count` | `.../collections/<id>/count` | `GET` | Item count per collection | `success`: >=1 collection counted; `skipped`: no collections; `denied`/`failed`: refused or errored |
| `chromadb_documents_sample` | `chromadb_documents_sample` | `.../collections/<id>/get` | `POST` | Bounded document/metadata sampling into `.content.jsonl` (no embeddings) | `skipped`: disabled by `content.*` policy or no collections; `success`: >=1 collection sampled |

## Graph and Evidence Mapping

- **Nodes:**
  - `ChromaInstance` (with `AIService` umbrella label), carrying the shared
    [service property contract](../02-graph-model.md#property-contract)
    (endpoint, access, `collection_count`, content summary, TLS),
    `software_version`, `software_version_raw`, `api_version`, and optional
    `tenant` / `database`.
  - `VectorCollection` nodes (`Contains` from `ChromaInstance`), carrying
    `collection_name`, `collection_id`, `tenant`, `database`, and
    `points_count`.
  - Fallback `NetworkEndpoint` when unmapped.
- **Edges:** `Contains`, `ObservedAt`.
- **Evidence sidecar:** `check_result` / access evidence, `fingerprint`, `tls`,
  `redirect`, and `correlation` records.
