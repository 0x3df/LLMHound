# Ray Dashboard collector

> **Status: Implemented — anonymous, read-only, bounded.** Companion to
> [design](../01-design.md),
> [graph model](../02-graph-model.md), and
> [capability matrix](../03-collector-capabilities.md).
> Implemented in `internal/collectors/ray`.

The Ray Dashboard collector performs anonymous, bounded, read-only enumeration
of Ray cluster dashboards (`/api/version`, `/api/cluster_status`, `/api/jobs/`,
`/api/v0/actors`) and bounded job entrypoint/environment content capture without
ever submitting or mutating jobs.

## Collection Policy and Safety

- **Read-Only & Anonymous:** No credentials are sent. All checks use HTTP `GET`
  only; `POST /api/jobs/` and mutating actor/job endpoints are never called.
- **Precision Identity Gate:** `/api/version` requires `ray_version` or
  `ray_commit` so Ollama `/api/version` responses never cross-match as Ray.
- **Content Tier (`ray_job_content`):** When `content.enabled` and
  `content.surfaces.ray` allow (default `true`), bounded job `entrypoint` and
  `runtime_env` payloads are written to `<prefix>.content.jsonl` (mode `0600`)
  through `internal/secrets`; matched secrets set `has_exposed_secret` /
  `secret_types` / `secret_last_confirmed` without storing raw values.
- **TLS & Redirects:** TLS verification is enforced by default unless
  `--insecure` is explicitly enabled and recorded.

## Allowlisted Operations

| Check ID | Operation | Endpoint | Method | Purpose | Outcome Semantics |
|---|---|---|---|---|---|
| `ray_version` | `ray_version` | `/api/version` | `GET` | Ray version, API version, and `ray_commit` (excluded from `anon_operations`) | `success`: Ray version JSON verified; `denied`: 401/403; `failed`: non-Ray JSON, 404, 429, or transport error |
| `ray_cluster_status` | `ray_cluster_status` | `/api/cluster_status` | `GET` | Cluster node summary | `success`: cluster status enumerated anonymously; `denied`: 401/403; `failed`: 404, malformed, or transport error |
| `ray_jobs` | `ray_jobs` | `/api/jobs/` | `GET` | Job listing metadata (also required check for the opt-in `ray-anonymous-jobs` path-qualification rule) | `success`: jobs enumerated anonymously; `denied`: 401/403; `failed`: 404, malformed, or transport error |
| `ray_actors` | `ray_actors` | `/api/v0/actors` | `GET` | Cluster actor count metadata | `success`: actors enumerated anonymously; `denied`: 401/403; `failed`: 404, malformed, or transport error |
| `ray_nodes` | `ray_nodes` | `/nodes?view=summary` | `GET` | Read-only alive worker host IPs (`worker_hosts`) for opt-in cluster fan-out | `success`: summary retrieved; `denied`: 401/403; `unsupported`: 404 or missing summary; `failed`: transport error |
| `ray_job_content` | `ray_job_content` | `/api/jobs/` | `GET` | Bounded job `entrypoint` / `runtime_env` capture into `.content.jsonl` | `skipped`: disabled by `content.*` policy or no job payloads; `success`: >=1 job captured |

## Graph and Evidence Mapping

- **Nodes:** `RayDashboard` (with `AIService` umbrella label), carrying the
  shared [service property contract](../02-graph-model.md#property-contract)
  (endpoint, access, `exec_surface: ["job_submit"]` with `inferred` basis,
  `commit`, `worker_hosts`, content summary, TLS), `software_version`, `software_version_raw`,
  `api_version`, `node_count`, `job_count`, and `actor_count`; fallback
  `NetworkEndpoint` when unmapped.
- **Edges:** `ObservedAt` (`RayDashboard` → mapped native node or
  `NetworkEndpoint`).
- **Evidence sidecar:** `check_result` / access evidence, `fingerprint`, `tls`,
  `redirect`, and `correlation` records.
