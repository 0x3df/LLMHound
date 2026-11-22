# OpenAI-compatible collector

> **Status: M2c generic OpenAI-compatible collector implemented.** Companion to
> [design](../01-design.md),
> [graph model](../02-graph-model.md), and
> [capability matrix](../03-collector-capabilities.md).
> Implemented in `internal/collectors/openaicompat`.

The generic OpenAI-compatible collector provides an honest fallback for
`/v1/models` endpoints when no specific product (such as vLLM or LiteLLM) is
proven, without invoking completion or embedding endpoints or guessing product
versions.

## Collection Policy and Safety

- **Read-Only & Anonymous:** No credentials are sent. Only `GET /v1/models` is
  issued; `/v1/chat/completions`, `/v1/completions`, and `/v1/embeddings` are
  forbidden at the transport layer.
- **Fallback Precedence:** Placed last in `discovery.BuiltinDefinitions()` and
  skipped by `internal/scanner` on any `host:port` where a specific surface
  already matched. Endpoints that return product-specific markers (e.g.,
  `owned_by: "vllm"` or `max_model_len`) fail closed in this collector.
- **Honest Unknown Versions:** `software_version` and `exec_surface` are never
  guessed from `/v1/models` alone; explicit `Server` / `X-Powered-By` headers
  are retained verbatim as `server_header` / `x_powered_by`.

## Allowlisted Operations

| Check ID | Operation | Endpoint | Method | Purpose | Outcome Semantics |
|---|---|---|---|---|---|
| `openai_compatible_models` | `openai_compatible_models` | `/v1/models` | `GET` | Served model catalog | `success`: `{"object":"list","data":[...]}` returned anonymously; `denied`: 401/403 with OpenAI-compatible auth error; `failed`: product-specific response, 404, 429, malformed, or transport error |

## Graph and Evidence Mapping

- **Nodes:**
  - `OpenAICompatibleEndpoint` (with `AIService` umbrella label), carrying the
    shared [service property contract](../02-graph-model.md#property-contract)
    (endpoint, access, `model_count`, TLS) plus optional `server_header` /
    `x_powered_by`.
  - `AIModel` nodes (`ProvidesModel` from `OpenAICompatibleEndpoint`), bounded
    by `bounds.max_items`.
  - Fallback `NetworkEndpoint` when unmapped.
- **Edges:** `ProvidesModel`, `ObservedAt`.
- **Evidence sidecar:** `check_result` / access evidence, `fingerprint`, `tls`,
  `redirect`, and `correlation` records.
