# LangServe collector

> **Status: Implemented — anonymous, read-only, bounded.** Companion to
> [design](../01-design.md),
> [graph model](../02-graph-model.md), and
> [capability matrix](../03-collector-capabilities.md).
> Implemented in `internal/collectors/langserve`.

The LangServe collector performs anonymous, bounded, read-only enumeration of
LangServe applications (`/openapi.json`, runnable input/output/config schemas,
and playground exposure) without ever invoking `/invoke`, `/batch`, `/stream`,
or `/stream_log`.

## Collection Policy and Safety

- **Read-Only & Anonymous:** No credentials are sent and no runnable endpoints
  (`/invoke`, `/batch`, `/stream`, `/stream_log`, `/stream_events`) are ever
  called. All requests use HTTP `GET`.
- **Precision Identity Gate & Version Distinction:** Generic FastAPI
  `/openapi.json` documents without LangServe runnable suffix patterns or
  explicit LangServe markers fail closed. OpenAPI `info.version` is stored as
  `api_version`, never `software_version`; `software_version` is populated only
  when explicitly reported via `X-LangServe-Version` or `info.x-langserve-version`.
- **Content Tier (`langserve_schemas`):** When `content.enabled` and
  `content.surfaces.langserve` allow (default `true`), bounded JSON schemas
  from `<route>/{input_schema,output_schema,config_schema}` are written to
  `<prefix>.content.jsonl` (mode `0600`) through `internal/secrets`.
- **TLS & Redirects:** TLS verification is enforced by default unless
  `--insecure` is explicitly enabled and recorded; redirects are bounded and
  rechecked per hop.

## Allowlisted Operations

| Check ID | Operation | Endpoint | Method | Purpose | Outcome Semantics |
|---|---|---|---|---|---|
| `langserve_openapi` | `langserve_openapi` | `/openapi.json` | `GET` | LangServe identity, `api_version`, and runnable route inventory | `success`: LangServe routes enumerated anonymously; `denied`: 401/403; `failed`: non-LangServe OpenAPI, 404, 429, or transport error |
| `langserve_schemas` | `langserve_schemas` | `<route>/{input,output,config}_schema` | `GET` | Bounded runnable schema validation and optional `.content.jsonl` capture | `success`: >=1 schema retrieved; `skipped`: no routes; `denied`/`failed`: refused or errored |
| `langserve_playground` | `langserve_playground` | `<route>/playground/` | `GET` | Check whether interactive playground UI is anonymously exposed | `success`: >=1 playground reachable without login; `skipped`: no playground routes; `denied`/`failed`: login/auth required or errored |

## Graph and Evidence Mapping

- **Nodes:**
  - `LangServeApp` (with `AIService` umbrella label), carrying the shared
    [service property contract](../02-graph-model.md#property-contract)
    (endpoint, access, content summary, TLS), `api_version`, `software_version` /
    `software_version_raw` (when explicitly reported), `runnable_count`,
    `runnable_routes`, and `playground_exposed`.
  - Fallback `NetworkEndpoint` when unmapped.
- **Edges:**
  - `ObservedAt` (`LangServeApp` → mapped native node or `NetworkEndpoint`).
- **Evidence sidecar:** `check_result` / access evidence, `fingerprint`, `tls`,
  `redirect`, and `correlation` records.
