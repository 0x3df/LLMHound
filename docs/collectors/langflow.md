# Langflow collector

> **Status: M2c Langflow collector implemented.** Companion to
> [design](../01-design.md),
> [graph model](../02-graph-model.md), and
> [capability matrix](../03-collector-capabilities.md).
> Implemented in `internal/collectors/langflow`.

The Langflow collector performs anonymous, bounded, read-only enumeration of
Langflow servers (`/api/v1/version`, `/api/v1/auto_login`, `/api/v1/flows/`,
`/api/v1/all`) and bounded flow definition capture without executing flows,
validating code, or retaining any auto-login tokens.

## Collection Policy and Safety

- **Read-Only & Anonymous:** No credentials are sent. `/api/v1/validate/code`,
  `/api/v1/run/*`, and `/api/v1/build/*` are never called.
- **No Auto-Login Token Retention:** `/api/v1/auto_login` is decoded strictly
  for posture (`token_type`, `auto_login`); any `access_token` or
  `refresh_token` in the response is discarded at decode time and never enters
  node properties, evidence, checkpoints, logs, or `.content.jsonl`.
- **Content Tier (`langflow_flow_bodies`):** When `content.enabled` and
  `content.surfaces.langflow` allow (default `true`), bounded flow `data`
  definitions go to `<prefix>.content.jsonl` (mode `0600`) through
  `internal/secrets`.
- **TLS & Redirects:** TLS verification is enforced by default unless
  `--insecure` is explicitly enabled and recorded.

## Allowlisted Operations

| Check ID | Operation | Endpoint | Method | Purpose | Outcome Semantics |
|---|---|---|---|---|---|
| `langflow_version` | `langflow_version` | `/api/v1/version` | `GET` | Langflow package version (excluded from `anon_operations`) | `success`: Langflow version verified; `denied`: 401/403; `failed`: non-Langflow JSON, 404, 429, or transport error |
| `langflow_auto_login` | `langflow_auto_login` | `/api/v1/auto_login` | `GET` | Auto-login posture check (token discarded) | `success`: auto-login enabled; `denied`: 400/401/403 or `auto_login: false`; `failed`: 404 or transport error |
| `langflow_flows` | `langflow_flows` | `/api/v1/flows/` | `GET` | Flow inventory metadata | `success`: flows enumerated anonymously; `denied`: 401/403; `failed`: 404, malformed, or transport error |
| `langflow_components` | `langflow_components` | `/api/v1/all` | `GET` | Component catalog count | `success`: catalog enumerated anonymously; `denied`: 401/403; `failed`: malformed or transport error |
| `langflow_flow_bodies` | `langflow_flow_bodies` | `/api/v1/flows/` | `GET` | Bounded flow body capture into `.content.jsonl` | `skipped`: disabled by `content.*` policy or no flow bodies; `success`: >=1 flow captured |

## Graph and Evidence Mapping

- **Nodes:** `LangflowInstance` (with `AIService` umbrella label), carrying
  the shared [service property contract](../02-graph-model.md#property-contract)
  (endpoint, access, `auth_advertised`, `exec_surface: ["code_eval", "workflow_exec"]`
  with `inferred` basis, content summary, TLS), `software_version`,
  `software_version_raw`, `auto_login_enabled`, `flow_count`, and
  `component_count`; fallback `NetworkEndpoint` when unmapped.
- **Edges:** `ObservedAt`.
- **Evidence sidecar:** `check_result` / access evidence, `fingerprint`, `tls`,
  `redirect`, and `correlation` records.
