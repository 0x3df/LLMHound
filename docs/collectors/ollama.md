# Ollama Collector Reference

> **Status: Implemented — anonymous, read-only, bounded.** Companion to
> [design](../01-design.md),
> [capability matrix](../03-collector-capabilities.md), and
> [graph model](../02-graph-model.md).
> Implemented in `internal/collectors/ollama` and `internal/transport`.

The Ollama collector remotely enumerates Ollama LLM inference server instances
anonymously, safely, and read-only using the shared HTTP transport, graph/evidence
output, and checkpoint journal contracts.

## Collection Policy and Safety

- **Read-Only & Anonymous:** No credentials are sent. The collector only performs
  allowlisted metadata operations.
- **Strictly No Generation or Mutations:** Mutating and generation endpoints
  (`/api/generate`, `/api/chat`, `/api/embed*`, `/v1/chat/completions`,
  `/v1/completions`, `/v1/embeddings`, `/api/pull`, `/api/push`, `/api/create`,
  `/api/delete`, `/api/copy`, `/api/blobs`) are strictly forbidden and rejected at
  the transport layer.
- **Default-On Content Tier, Secret Detection & Provenance:** `/api/show` runs by
  default under the `content.*` policy (disable globally via `--content=false` or
  per surface via `--content-disable=ollama` / `content.surfaces.ollama: false`).
  Redacted metadata (`parent_model`, `license`, details `family`) is kept on
  `AIModel` nodes, while system prompts, modelfiles, and templates are written
  strictly within configured `content.*` bounds into `<prefix>.content.jsonl`
  (mode `0600`), scanned by `internal/secrets` (replacing verified secret spans
  with `[secret:<type>]` and recording `detected_exposures` in `.evidence.jsonl`),
  and summarized on `OllamaInstance` (`content_bytes`, `content_truncated`,
  `system_prompt_present`, `config_collected`, `has_exposed_secret`,
  `secret_types`, `secret_last_confirmed`). Content bodies and raw secret values
  never enter graph payloads, sidecars, checkpoints, or logs.
- **Bounded Resource Limits:** Respects configured `max_response_bytes`,
  `max_items` (truncating `/api/tags` and `/api/ps` enumeration with `CoverageTruncated`
  when exceeded), `content.*` byte/item limits, `connect_timeout`, and `response_timeout`.
- **TLS & Redirects:** Captures leaf certificate details (fingerprint, issuer,
  subject, SANs, validity, negotiated version). Halts on TLS verification failure
  unless `--insecure` is explicitly enabled. Bounded redirects; a hop must stay on the original request host or an explicitly authorized host. TLS and redirect evidence is captured per request across all checks.

## Allowlisted Operations

| Check ID | Operation | Endpoint | Method | Purpose | Outcome Semantics |
|---|---|---|---|---|---|
| `ollama_version` | `ollama_version` | `/api/version` | GET | Runtime software version | `success`: valid version JSON; `denied`: 401/403; `failed`: 404, malformed, or transport error |
| `ollama_tags` | `ollama_tags` | `/api/tags` | GET | Model catalog & metadata | `success`: anonymous catalog listed; `denied`: 401/403; `failed`: 404 or malformed |
| `ollama_ps` | `ollama_ps` | `/api/ps` | GET | Running models in memory | `success`: running models listed; `denied`: 401/403; `failed`: 404 (unavailable in older releases), malformed, or truncated; running models bounded by `max_items` |
| `ollama_show` | `ollama_show` | `/api/show` | POST | Model provenance and bounded content | `skipped`: disabled by `content.*` policy (`content.enabled: false` or `surfaces.ollama: false`) or empty model catalog; `success`: provenance/content retrieved within `content.*` bounds for at least one model (reason gives N of M); `failed`: no model succeeded, including `max_response_bytes` truncation |

## Graph and Evidence Mapping

- **Nodes:**
  - `OllamaInstance` carrying `AIService` umbrella label, with the shared [service property contract](../02-graph-model.md#property-contract) (endpoint, access, `exec_surface`, content summary, TLS)
    plus `software_version` and `software_version_raw`. `exec_surface` is `model_mutation`
    (`inferred` from product identity; nothing is pulled or deleted).
  - `AIModel` nodes for each enumerated model, scoped to the owning service ID,
    with properties `name`, `digest`, `size`, `format`, `family`, `parameter_size`,
    `quantization_level`, `parent_model`, `modified_at`, plus `running`/`size_vram`
    from `ollama_ps` and `license`/`provenance_source` from `ollama_show`.
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

- `complete`: `ollama_version` and `ollama_tags` succeeded, no truncation, and no `ollama_ps` or active `ollama_show` degradation. Target status `completed`.
- `truncated`: `ollama_tags` succeeded but the catalog or running models exceeded `max_items`, a body hit `max_response_bytes`, or `/api/show` content hit `content.*` bounds. Target status `partial`.
- `partial`: At least one check succeeded while another (including `ollama_ps` or active `ollama_show`) failed or was denied. Target status `partial`.
- `failed`: Unreachable target or all checks failed. Target status `failed`.
