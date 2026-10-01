# Ollama Collector Reference

> **Status: M2a Ollama collector implemented.** Companion to
> [`docs/plans/2026-09-29-llmhound-design.md`](../plans/2026-09-29-llmhound-design.md),
> [`docs/reference/collector-capabilities.md`](collector-capabilities.md), and
> [`docs/reference/graph-model.md`](graph-model.md).
> Implemented in `internal/collectors/ollama` and `internal/transport`.

The Ollama collector remotely enumerates Ollama LLM inference server instances
anonymously, safely, and read-only. It consumes the landed discovery/transport,
graph/evidence output, and checkpoint journal contracts.

## Collection Policy and Safety

- **Read-Only & Anonymous:** No credentials are sent. The collector only performs
  allowlisted metadata operations.
- **Strictly No Generation or Mutations:** Mutating and generation endpoints
  (`/api/generate`, `/api/chat`, `/api/embed*`, `/v1/chat/completions`,
  `/v1/completions`, `/v1/embeddings`, `/api/pull`, `/api/push`, `/api/create`,
  `/api/delete`, `/api/copy`, `/api/blobs`) are strictly forbidden and rejected at
  the transport layer.
- **Opt-In Provenance:** `/api/show` requires explicit opt-in (`--prompts`,
  `--configuration-content`, or `--resource-content`); when disabled (the default)
  it is skipped. Only bounded, redacted provenance is kept (`parent_model`,
  `license`, details `family`); modelfile, system prompt, and template content are
  never persisted.
- **Bounded Resource Limits:** Respects configured `max_response_bytes`,
  `max_items` (truncating catalog enumeration with `CoverageTruncated` when
  exceeded), `connect_timeout`, and `response_timeout`.
- **TLS & Redirects:** Captures leaf certificate details (fingerprint, issuer,
  subject, SANs, validity, negotiated version). Halts on TLS verification failure
  unless `--insecure` is explicitly enabled. Bounded redirects; a hop must stay on the original request host or an explicitly authorized host. TLS and redirect evidence is captured per request across all checks.

## Allowlisted Operations

| Check ID | Operation | Endpoint | Method | Purpose | Outcome Semantics |
|---|---|---|---|---|---|
| `ollama_version` | `ollama_version` | `/api/version` | GET | Runtime software version | `success`: valid version JSON; `denied`: 401/403; `failed`: 404, malformed, or transport error |
| `ollama_tags` | `ollama_tags` | `/api/tags` | GET | Model catalog & metadata | `success`: anonymous catalog listed; `denied`: 401/403; `failed`: 404 or malformed |
| `ollama_ps` | `ollama_ps` | `/api/ps` | GET | Running models in memory | `success`: running models listed; `denied`: 401/403; `failed`: 404 (unavailable in older releases), malformed, or truncated; running models bounded by `max_items` |
| `ollama_show` | `ollama_show` | `/api/show` | POST | Redacted model provenance | `skipped`: default (opt-in disabled); `success`: provenance retrieved for at least one model (reason gives N of M); `failed`: no model succeeded, including truncated responses |

## Graph and Evidence Mapping

- **Nodes:**
  - `OllamaInstance` carrying `AIService` umbrella label, with properties `endpoint_host`,
    `endpoint_port`, `product`, `vendor`, `software_version`, `software_version_raw`,
    `tls_verification`, `tls_fingerprint`.
  - `AIModel` nodes for each enumerated model, scoped to the owning service ID,
    with properties `name`, `digest`, `size`, `format`, `family`, `parameter_size`,
    `quantization_level`, `parent_model`, `modified_at`, plus `running`/`size_vram`
    from `ollama_ps` and `license`/`provenance_source` from opt-in `ollama_show`.
  - Fallback `NetworkEndpoint` when target does not correlate to an existing AD `Computer`.
- **Edges:**
  - `UnauthenticatedAccess` (`CollectionVantage` → `OllamaInstance`) upon validated anonymous
    `ollama_tags` enumeration success.
  - `ProvidesModel` (`OllamaInstance` → `AIModel`) for each model in catalog.
  - `ObservedAt` (`OllamaInstance` → `Computer` or `NetworkEndpoint`).
- **Sidecar Evidence:**
  - Check result records for each operation (`RecordCheckResult`).
  - Runtime fingerprint record (`RecordFingerprint`).
  - TLS observation record (`RecordTLS`) when TLS is used.
  - Correlation record (`RecordCorrelation`).
  - Redirect record (`RecordRedirect`) when redirects occur.

## Target Status and Coverage

- `complete`: `ollama_version` and `ollama_tags` succeeded, no truncation, and no `ollama_ps` or opted-in `ollama_show` degradation. Target status `completed`.
- `truncated`: `ollama_tags` succeeded but the catalog or running models exceeded `max_items`, or a body hit `max_response_bytes`. Target status `partial`.
- `partial`: At least one check succeeded while another (including `ollama_ps` or opted-in `ollama_show`) failed or was denied. Target status `partial`.
- `failed`: Unreachable target or all checks failed. Target status `failed`.
