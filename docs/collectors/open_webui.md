# Open WebUI collector

> **Status: Implemented — anonymous, read-only, bounded.** Companion to
> [design](../01-design.md),
> [graph model](../02-graph-model.md), and
> [capability matrix](../03-collector-capabilities.md).
> Implemented in `internal/collectors/openwebui`.

The Open WebUI collector performs anonymous, bounded, read-only enumeration of
Open WebUI instances (`/api/version`, `/api/config`, `/api/models`) and bounded
configuration capture without signing up, logging in, or calling inference or
backend endpoints.

## Collection Policy and Safety

- **Read-Only & Anonymous:** No credentials are sent. All checks use HTTP `GET`
  only; signup, signin, chat completion, and backend proxy routes are never
  called.
- **Precision Identity Gate:** Because `/api/version` shares its
  `{"version": "..."}` JSON shape with Ollama, Open WebUI requires
  product-specific evidence from `/api/config` (`features`, `name`,
  `default_models`, `onboarding`, or backend URL lists) or explicit Open WebUI
  headers/denial bodies; `/api/version` alone fails closed.
- **Content Tier & Backends (`open_webui_config_content`):** Declared backend
  URLs are sanitized via userinfo/query/fragment stripping into `backend_refs`
  without scanning them. When `content.enabled` and `content.surfaces.open_webui`
  allow (default `true`), the `/api/config` JSON body is written to
  `<prefix>.content.jsonl` (mode `0600`) through `internal/secrets`.
- **TLS & Redirects:** TLS verification is enforced by default unless
  `--insecure` is explicitly enabled and recorded; redirects are bounded and
  rechecked per hop.

## Allowlisted Operations

| Check ID | Operation | Endpoint | Method | Purpose | Outcome Semantics |
|---|---|---|---|---|---|
| `open_webui_version` | `open_webui_version` | `/api/version` | `GET` | Application version metadata (excluded from `anon_operations`) | `success`: version JSON returned; `denied`: 401/403; `failed`: 404, 429, malformed, or transport error |
| `open_webui_config` | `open_webui_config` | `/api/config` | `GET` | Auth/signup flags and declared backend URLs (excluded from `anon_operations`) | `success`: Open WebUI config verified; `denied`: 401/403; `failed`: non-Open WebUI JSON, 404, 429, or transport error |
| `open_webui_models` | `open_webui_models` | `/api/models` | `GET` | Exposed model catalog | `success`: models enumerated anonymously; `denied`: 401/403; `failed`: 404, 429, malformed, or transport error |
| `open_webui_config_content` | `open_webui_config_content` | `/api/config` | `GET` | Bounded configuration capture into `.content.jsonl` | `skipped`: disabled by `content.*` policy or config unavailable; `success`: config captured |

## Graph and Evidence Mapping

- **Nodes:**
  - `OpenWebUIInstance` (with `AIService` umbrella label), carrying the shared
    [service property contract](../02-graph-model.md#property-contract)
    (endpoint, access, `auth_advertised`, `backend_refs`, `model_count`,
    content summary, TLS), `software_version`, `software_version_raw`, and
    `signup_enabled`.
  - `AIModel` nodes (bounded by `bounds.max_items`), carrying `model_id`,
    `display_name`, and `owned_by`.
  - Fallback `NetworkEndpoint` when unmapped.
- **Edges:**
  - `ProvidesModel` (`OpenWebUIInstance` → `AIModel`).
  - `ObservedAt` (`OpenWebUIInstance` → mapped native node or `NetworkEndpoint`).
- **Evidence sidecar:** `check_result` / access evidence, `fingerprint`, `tls`,
  `redirect`, and `correlation` records.
