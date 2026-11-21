# Ollama Collector Reference

> **Status: M2a Ollama collector implemented.** Companion to
> [design](../01-design.md),
> [capability matrix](../03-collector-capabilities.md), and
> [graph model](../02-graph-model.md).
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
  - `OllamaInstance` carrying `AIService` umbrella label, with the shared [service property contract](../02-graph-model.md#property-contract) (endpoint, access, `exec_surface`, TLS)
    plus `software_version` and `software_version_raw`. `exec_surface` is `model_mutation`
    (`inferred` from product identity; nothing is pulled or deleted).
  - `AIModel` nodes for each enumerated model, scoped to the owning service ID,
    with properties `name`, `digest`, `size`, `format`, `family`, `parameter_size`,
    `quantization_level`, `parent_model`, `modified_at`, plus `running`/`size_vram`
    from `ollama_ps` and `license`/`provenance_source` from opt-in `ollama_show`.
  - Fallback `NetworkEndpoint` when the asset mapping does not name an existing BloodHound node for the target.
- **Edges:**
  - `ProvidesModel` (`OllamaInstance` → `AIModel`) for each model in catalog.
  - `ObservedAt` (`OllamaInstance` → the existing native node the mapping names, or `NetworkEndpoint`).
- **Anonymous access** is properties on the `OllamaInstance`, not an edge: `anon_operations`
  lists `ollama_tags` when the catalog listing succeeds anonymously, and `auth_observed` is
  `anonymous`, `denied` (any 401/403), `mixed`, or `unknown`.
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
