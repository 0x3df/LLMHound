# Flowise collector

> **Status: M2c Flowise collector implemented.** Companion to
> [design](../01-design.md),
> [graph model](../02-graph-model.md), and
> [capability matrix](../03-collector-capabilities.md).
> Implemented in `internal/collectors/flowise`.

The Flowise collector performs anonymous, bounded, read-only enumeration of
Flowise servers (`/api/v1/version`, `/api/v1/chatflows`) and bounded flow
configuration capture without calling prediction endpoints.

## Collection Policy and Safety

- **Read-Only & Anonymous:** No credentials are sent. All checks use HTTP `GET`
  only; `/api/v1/prediction/*` endpoints are never called.
- **Precision Identity Gate:** Rejects Langflow `/api/v1/version` payloads
  carrying `package: "Langflow"` or `main_version`.
- **Content Tier (`flowise_flow_config`):** When `content.enabled` and
  `content.surfaces.flowise` allow (default `true`), bounded chatflow `flowData`
  definitions are written to `<prefix>.content.jsonl` (mode `0600`) through
  `internal/secrets`.
- **TLS & Redirects:** TLS verification is enforced by default unless
  `--insecure` is explicitly enabled and recorded.

## Allowlisted Operations

| Check ID | Operation | Endpoint | Method | Purpose | Outcome Semantics |
|---|---|---|---|---|---|
| `flowise_version` | `flowise_version` | `/api/v1/version` | `GET` | Flowise version (excluded from `anon_operations`) | `success`: version JSON verified; `denied`: 401/403; `failed`: Langflow/non-Flowise JSON, 404, or transport error |
| `flowise_chatflows` | `flowise_chatflows` | `/api/v1/chatflows` | `GET` | Chatflow inventory and `isPublic` counts | `success`: chatflows listed anonymously; `denied`: 401/403; `failed`: 404, malformed, or transport error |
| `flowise_flow_config` | `flowise_flow_config` | `/api/v1/chatflows` | `GET` | Bounded `flowData` capture into `.content.jsonl` | `skipped`: disabled by `content.*` policy or no `flowData`; `success`: >=1 flow captured |

## Graph and Evidence Mapping

- **Nodes:** `FlowiseInstance` (with `AIService` umbrella label), carrying the
  shared [service property contract](../02-graph-model.md#property-contract)
  (endpoint, access, `exec_surface: ["workflow_exec"]` with `inferred` basis,
  content summary, TLS), `software_version`, `software_version_raw`,
  `chatflow_count`, and `public_chatflow_count`; fallback `NetworkEndpoint` when
  unmapped.
- **Edges:** `ObservedAt`.
- **Evidence sidecar:** `check_result` / access evidence, `fingerprint`, `tls`,
  `redirect`, and `correlation` records.
