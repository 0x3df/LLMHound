# vLLM collector

> **Status: Implemented — anonymous, read-only, bounded.** Companion to
> [design](../01-design.md),
> [graph model](../02-graph-model.md), and
> [capability matrix](../03-collector-capabilities.md).
> Implemented in `internal/collectors/vllm`.

The vLLM collector performs anonymous, bounded, read-only enumeration of vLLM
inference servers without invoking completion or embedding endpoints and without
misclassifying generic OpenAI-compatible servers as vLLM.

## Collection Policy and Safety

- **Read-Only & Anonymous:** No credentials are sent. Only HTTP `GET` requests
  to `/version` and `/v1/models` are issued. Inference endpoints
  (`/v1/chat/completions`, `/v1/completions`, `/v1/embeddings`) are forbidden at
  the transport layer and never called.
- **Precision Identity Gate:** An OpenAI-compatible `/v1/models` response alone
  does not prove vLLM. The collector emits a `VLLMInstance` node only when
  vLLM-specific evidence is observed: a successful `GET /version` response, a
  `Server` header naming `vllm`, or a model entry carrying `owned_by: "vllm"` or
  `max_model_len`. Generic OpenAI-compatible responses fail closed with no
  service node emitted.
- **Honest Unknown Versions:** When `/version` is unavailable (e.g., 404) or a
  proxy banner masks it while `/v1/models` identifies vLLM, `software_version`
  and `software_version_raw` remain unset and coverage is `partial`.
- **TLS & Redirects:** TLS verification is enforced by default unless
  `--insecure` is explicitly configured and recorded; redirects are bounded and
  rechecked per hop.

## Allowlisted Operations

| Check ID | Operation | Endpoint | Method | Purpose | Outcome Semantics |
|---|---|---|---|---|---|
| `vllm_version` | `vllm_version` | `/version` | `GET` | Runtime version metadata (excluded from `anon_operations`) | `success`: valid version JSON; `denied`: HTTP 401/403; `failed`: 404, 429, malformed, truncated, or transport error |
| `vllm_models` | `vllm_models` | `/v1/models` | `GET` | Served model and alias catalog | `success`: vLLM-confirmed models listed anonymously; `denied`: HTTP 401/403; `failed`: lacks vLLM identity, 404, 429, malformed, truncated, or transport error |

## Graph and Evidence Mapping

- **Nodes:**
  - `VLLMInstance` (with `AIService` umbrella label), carrying the shared
    [service property contract](../02-graph-model.md#property-contract)
    (endpoint, access, `model_count` when `vllm_models` succeeded, TLS),
    `software_version`, and `software_version_raw`. `exec_surface` is omitted
    (serving inference alone is not an execution surface).
  - `AIModel` nodes (bounded by `bounds.max_items`), scoped by service ID and
    exact model ID, carrying `model_id`, `owned_by`, `root`, `parent`,
    `max_model_len`, and `created`.
  - Fallback `NetworkEndpoint` when the asset mapping does not name an existing
    BloodHound node for the target.
- **Edges:**
  - `ProvidesModel` (`VLLMInstance` → `AIModel`).
  - `ObservedAt` (`VLLMInstance` → mapped native node or `NetworkEndpoint`).
- **Access properties:** `anon_operations` lists `vllm_models` only when model
  enumeration succeeded anonymously (`vllm_version` never populates it).
- **Evidence sidecar:** `check_result` / access evidence, `fingerprint`, `tls`,
  `redirect`, and `correlation` records.
