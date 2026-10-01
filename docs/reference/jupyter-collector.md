# Jupyter Collector Reference

> **Status: M2a Jupyter collector implemented.** Companion to
> [`docs/plans/2026-09-29-llmhound-design.md`](../plans/2026-09-29-llmhound-design.md),
> [`docs/reference/graph-model.md`](graph-model.md), and
> [`docs/reference/collector-capabilities.md`](collector-capabilities.md).
> Implemented in `internal/collectors/jupyter`.

The Jupyter collector performs anonymous, bounded, read-only remote enumeration
of Jupyter notebook and server instances (Jupyter Server, Jupyter Notebook, JupyterLab).
It produces structured OpenGraph nodes, edges, sidecar evidence records, and
journal entries without performing code execution, mutations, or downloading file contents.

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

The collector strictly executes only three allowlisted read-only checks:

| Check ID | Operation | Endpoint | Method | Purpose |
|---|---|---|---|---|
| `jupyter_version` | `jupyter_api_version` | `/api` | `GET` | Retrieve reported API version and server version metadata |
| `jupyter_sessions` | `jupyter_sessions` | `/api/sessions` | `GET` | Enumerate active session count, kernel names, and execution states |
| `jupyter_contents` | `jupyter_contents_list` | `/api/contents` | `GET` | Enumerate top-level workspace notebook and file metadata without bodies |

### Safety Constraints

1. **No Code Execution**: Endpoints that spawn or execute code (e.g. `POST /api/kernels`,
   WebSocket channels on `/api/kernels/<id>/channels`) are never contacted.
2. **No Mutations**: Only HTTP `GET` requests are issued. Mutation endpoints (`POST`, `PUT`,
   `DELETE`, `PATCH`) are never called.
3. **No Default File Content Reads**: File and notebook contents are never fetched. Only directory
   metadata (names, paths, types, sizes, timestamps) is enumerated from `/api/contents`.
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

- **`LLMHound_JupyterServer`**: Scoped service node carrying `product`, `vendor`, `api_version`,
  `endpoint_host`, `endpoint_port`, `auth_required`, `active_sessions`, and `kernels`.
- **`LLMHound_AIService`**: Multi-kind umbrella label carried by the server node.
- **`LLMHound_WorkspaceFile`**: Resource node for each enumerated notebook or file, scoped by
  service ID and resource path key (`item.Path`).
- **`LLMHound_CollectionVantage`**: Observation vantage node.
- **`LLMHound_NetworkEndpoint`**: Fallback network endpoint node when target does not correlate to
  an existing AD `Computer`. (When target correlates to a native `Computer`, no `NetworkEndpoint`
  node is created).

### Edges Emitted

- **`LLMHound_Contains`**: Topology edge from `JupyterServer` to each enumerated `WorkspaceFile`.
- **`LLMHound_UnauthenticatedAccess`**: Access edge from `CollectionVantage` to `JupyterServer`,
  emitted only when workspace contents or sessions enumeration succeeds anonymously.
- **`LLMHound_ObservedAt`**: Topology edge from `JupyterServer` to either the correlated AD
  `Computer` (native-linking, without `source_kind`) or fallback `NetworkEndpoint`.

## Evidence Sidecar Emission

The collector emits structured evidence records into the `.evidence.jsonl` sidecar:
- **`check_result`**: Per-check outcome (`success`, `denied`, `failed`), reason, and HTTP details.
- **`fingerprint`**: Reported API version, product ("Jupyter Server"), vendor ("Project Jupyter"),
  and observation method ("api_version").
- **`correlation`**: Decision provenance linking target to AD Computer or NetworkEndpoint fallback.
- **`tls`**: When collecting over HTTPS, leaf certificate SHA-256 fingerprint, issuer, subject,
  SANs, validity interval, and negotiated TLS version.
