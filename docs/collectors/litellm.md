# LiteLLM collector

> **Status: Implemented — anonymous, read-only, bounded.** Companion to
> [design](../01-design.md),
> [graph model](../02-graph-model.md), and
> [capability matrix](../03-collector-capabilities.md).
> Implemented in `internal/collectors/litellm`.

The LiteLLM collector performs anonymous, bounded, read-only enumeration of
LiteLLM proxy gateways (`/openapi.json`, `/v1/models`, `/model/info`) and
bounded configuration capture without calling completion, spend, or
key-management endpoints.

## Collection Policy and Safety

- **Read-Only & Anonymous:** No credentials are sent. All checks use HTTP `GET`
  only; `/v1/chat/completions`, `/v1/completions`, `/key/*`, `/spend/*`, and
  `/model/new` are never called.
- **Precision Identity Gate:** Generic `/v1/models` responses without LiteLLM
  evidence (`info.title` / route markers in `/openapi.json`, `X-LiteLLM-*`
  headers, or `litellm_params` in `/model/info`) fail closed with zero nodes.
- **Sanitized Backends & Content Tier (`litellm_config`):** `api_base` URLs
  from `/model/info` are stripped of userinfo, query parameters, and fragments
  before entering `backend_refs`. When `content.enabled` and
  `content.surfaces.litellm` allow (default `true`), bounded `/model/info` and
  optional `/settings` bodies go to `<prefix>.content.jsonl` (mode `0600`)
  through `internal/secrets`; matched secrets set `has_exposed_secret` /
  `secret_types` / `secret_last_confirmed` without retaining raw values.
- **TLS & Redirects:** TLS verification is enforced by default unless
  `--insecure` is explicitly enabled and recorded; redirects are bounded and
  rechecked per hop.

## Allowlisted Operations

| Check ID | Operation | Endpoint | Method | Purpose | Outcome Semantics |
|---|---|---|---|---|---|
| `litellm_openapi` | `litellm_openapi` | `/openapi.json` | `GET` | LiteLLM OpenAPI identity, `api_version`, and advertised key-management routes (excluded from `anon_operations`) | `success`: LiteLLM OpenAPI verified; `denied`: 401/403; `failed`: non-LiteLLM JSON, 404, 429, truncated, or transport error |
| `litellm_models` | `litellm_models` | `/v1/models` | `GET` | Served model catalog | `success`: models listed anonymously; `denied`: 401/403; `failed`: 404, 429, malformed, or transport error |
| `litellm_model_info` | `litellm_model_info` | `/model/info` | `GET` | Provider aliases and sanitized backend references (`api_base`) | `success`: model info enumerated anonymously; `denied`: 401/403; `failed`: 404, 429, malformed, or transport error |
| `litellm_config` | `litellm_config` | `/model/info`, `/settings` | `GET` | Bounded configuration capture into `.content.jsonl` | `skipped`: disabled by `content.*` policy or unconfirmed; `success`: >=1 config body captured; `denied`/`failed`: refused or errored |

## Graph and Evidence Mapping

- **Nodes:**
  - `LiteLLMGateway` (with `AIService` umbrella label), carrying the shared
    [service property contract](../02-graph-model.md#property-contract)
    (endpoint, access, `backend_refs`, `model_count`, content summary, TLS),
    `api_version`, `software_version` / `software_version_raw` (only when
    reported via `X-LiteLLM-Version`), and `key_management_routes_advertised`.
  - `AIModel` nodes (bounded by `bounds.max_items`), carrying `model_id`,
    `owned_by`, `provider`, `backend_model`, and `created`.
  - Fallback `NetworkEndpoint` when unmapped.
- **Edges:**
  - `ProvidesModel` (`LiteLLMGateway` → `AIModel`).
  - `ObservedAt` (`LiteLLMGateway` → mapped native node or `NetworkEndpoint`).
- **Evidence sidecar:** `check_result` / access evidence, `fingerprint`, `tls`,
  `redirect`, and `correlation` records.
