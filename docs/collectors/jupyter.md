# Jupyter Collector Reference

> **Status: M2a + D3 + D4 Jupyter collector implemented.** Companion to
> [design](../01-design.md),
> [graph model](../02-graph-model.md), and
> [capability matrix](../03-collector-capabilities.md).
> Implemented in `internal/collectors/jupyter`.

The Jupyter collector performs anonymous, bounded, read-only remote enumeration
of Jupyter notebook and server instances (Jupyter Server, Jupyter Notebook, JupyterLab).
It produces structured OpenGraph nodes, edges, sidecar evidence records,
restricted `.content.jsonl` entries (when enabled under `content.*`), and journal
entries without executing kernels or mutating server state.

## Discovery Gate

Before any check runs, the collector calls `discovery.Probe` with the shared
`discovery.JupyterDefinition()` fingerprint (`internal/discovery/fingerprint.go`).
Only Jupyter-specific evidence matches: a `jupyter` Server header or
`X-Jupyter-Version` header, a Jupyter-shaped 200 body, a 401/403 body naming
Jupyter, or a `/login?next=` redirect targeting `/tree` or `/lab`. Generic JSON
version bodies, generic auth errors, bare `Server: tornado`, and generic `/login`
redirects do not match. An unmatched target yields a `failed` result with the reason
(`target not identified as jupyter` or `target unreachable`) and emits no graph nodes.

## Allowlisted Operations

The collector strictly executes only allowlisted read-only checks:

| Check ID | Operation | Endpoint | Method | Purpose |
|---|---|---|---|---|
| `jupyter_version` | `jupyter_api_version` | `/api` | `GET` | Retrieve reported API version and server version metadata |
| `jupyter_sessions` | `jupyter_sessions` | `/api/sessions` | `GET` | Enumerate active session count, kernel names, and execution states |
| `jupyter_contents` | `jupyter_contents_list` | `/api/contents` | `GET` | Enumerate top-level workspace notebook and file metadata without bodies |
| `jupyter_file_content` | `jupyter_file_content` | `/api/contents/<path>?content=1` | `GET` | Bounded read of non-binary notebook and text workspace files into `.content.jsonl` (excluded from `anon_operations`; skipped if disabled by `content.*` policy) |

### Safety Constraints

1. **No Code Execution**: Endpoints that spawn or execute code (e.g. `POST /api/kernels`,
   WebSocket channels on `/api/kernels/<id>/channels`) are never contacted.
2. **No Mutations**: Only HTTP `GET` requests are issued. Mutation endpoints (`POST`, `PUT`,
   `DELETE`, `PATCH`) are never called.
3. **Bounded Content Reads, Secret Detection & Binary Exclusion**: When `content.enabled` and
   `content.surfaces.jupyter` allow (default `true` via CLI/config), `jupyter_file_content`
   fetches non-binary notebooks and workspace text files listed under `/api/contents` into
   `<prefix>.content.jsonl` (mode `0600`), bounded by `content.max_item_bytes`,
   `content.max_items_per_resource`, and `content.max_service_bytes`. Binary extensions,
   `base64` encodings, binary MIME types, and null-byte payloads are skipped, and content
   bodies never enter graph payloads, sidecar records, or journals. High-precision secret
   detectors (`internal/secrets`) scan collected bodies, replace verified matches with
   `[secret:<type>]`, record `detected_exposures` by type and location in `.evidence.jsonl`,
   and summarize `JupyterServer` with `content_bytes`, `content_truncated`, `has_exposed_secret`,
   `secret_types`, and `secret_last_confirmed`. Disable with `--content=false` or
   `--content-disable=jupyter`.
4. **Authentication Boundaries**: The collector stops at authentication boundaries. HTTP 401/403
   responses and HTTP 200/302 HTML login pages are recognized as honest access denials (`denied`),
   not mistaken for successful API enumeration.
5. **Bounded Listings**: Workspace file enumeration is bounded by `config.Bounds.MaxItems`
   (default 10,000), as are sessions. When items exceed the limit, enumeration stops and
   reports `CoverageTruncated`.
   Only the root directory is listed; subdirectories are not recursed, and when any are
   skipped coverage is `partial` with a "root listing only" reason. Coverage is `complete`
   only when every check succeeds and nothing was truncated or skipped.
6. **Redaction**: URL credentials, query strings, and sensitive token/password substrings in paths
   or session metadata are stripped or redacted with `[REDACTED]`.

## Graph Model Emission

### Nodes Emitted

- **`LLMHound_JupyterServer`**: Scoped service node carrying the shared property contract
  (endpoint, access, TLS), `api_version`, `auth_required`, `active_sessions`, `kernels`, and
  `exec_surface = [code_kernel]` (`inferred` from product identity; no kernel is started).
  Access properties are described below.
- **`LLMHound_AIService`**: Multi-kind umbrella label carried by the server node.
- **`LLMHound_WorkspaceFile`**: Resource node for each enumerated notebook or file, scoped by
  service ID and resource path key (`item.Path`).
- **`LLMHound_NetworkEndpoint`**: Fallback node when the asset mapping does not name an existing
  BloodHound node for the target. (When it does, no `NetworkEndpoint` node is created.)

### Edges Emitted

- **`LLMHound_Contains`**: Topology edge from `JupyterServer` to each enumerated `WorkspaceFile`.
- **`LLMHound_ObservedAt`**: Topology edge from `JupyterServer` to either the existing
  native node the mapping names (a native-linking edge, emitted without `source_kind`) or the
  fallback `NetworkEndpoint`.

### Anonymous access (properties, not edges)

Access is recorded on the `JupyterServer` node from the **enumeration** checks only
(`jupyter_contents` and `jupyter_sessions`):

- `auth_observed`: `anonymous` (an enumeration check succeeded anonymously), `denied`,
  `mixed`, or `unknown`.
- `anon_operations`: the check IDs that succeeded anonymously (omitted when none did).

`jupyter_version` and `jupyter_file_content` are deliberately excluded from `anon_operations`:
Jupyter exposes version metadata even when authentication is enabled, and `anon_operations`
records enumeration checks only (not content-tier reads). An HTML login page is not a successful listing.

## Evidence Sidecar Emission

The collector emits structured evidence records into the `.evidence.jsonl` sidecar:
- **`check_result`**: Per-check outcome (`success`, `denied`, `failed`), reason, and HTTP details.
- **`fingerprint`**: Reported API version, product ("Jupyter Server"), vendor ("Project Jupyter"),
  and observation method ("api_version").
- **`correlation`**: Decision provenance linking target to an existing native BloodHound node or NetworkEndpoint fallback.
- **`tls`**: When collecting over HTTPS, leaf certificate SHA-256 fingerprint, issuer, subject,
  SANs, validity interval, and negotiated TLS version.
