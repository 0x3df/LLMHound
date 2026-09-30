# Collector capability matrix

**Status: revised draft; not implemented.** This is the v1 collection contract
for the [design](../plans/2026-09-29-llmhound-design.md) and
[graph model](graph-model.md), not a claim that every product release exposes
every field anonymously. Exact operations and supported releases must be verified
against official product/protocol documentation and recorded in collector tests.

## Default collection policy

All default checks are anonymous, bounded, allowlisted metadata operations.
Validate operation semantics, not just HTTP method: some read-only APIs use POST,
and GET alone does not guarantee a safe operation. Transport initialization may
establish a protocol session; it must not initiate application workloads.
Stop at authentication boundaries. No credentials are sent to scanned services.

Existing optional resource/content reads require explicit opt-in, authorization,
size limits, and redaction. Metadata collection must remain useful without them.
Tool descriptions, read-only annotations, and advertised URLs are untrusted
metadata, not permission to expand collection. Never follow a dependency or
redirect outside the authorized target scope; recheck resolved addresses on each
connection and redirect hop. Disable automatic cross-scope redirect following.

## Common checks for every collector

- **Fingerprint/version:** attempt documented public metadata discovery. Preserve
  product/vendor, raw reported software version, normalized version only when
  unambiguous, source operation/field, confidence, and time. Keep build/commit/image
  digest when explicitly reported. Unknown is an acceptable result; guessed
  versions are not. Do not identify a backend version from a proxy's banner.
- **Access posture:** record the outcome of each metadata/listing operation from
  its collection vantage. Listing, metadata retrieval, and optional content reads
  are separate observations; an HTTP 200 login page is not a successful listing.
- **Endpoint/deployment:** canonical endpoint, virtual host, base path, observed
  addresses, authorized redirect destinations, and explicitly reported deployment
  identifiers. Network location alone does not prove runtime placement.
- **Dependencies:** retain sanitized reported backend/provider/storage references
  without fetching them. Emit typed relationships only when the target meets the
  graph model's independent identification requirements.
- **TLS when applicable:** leaf certificate SHA-256 fingerprint, subject/SANs,
  issuer, validity interval, verification outcome/reason, and negotiated protocol
  when available. Capture only metadata available from the attempted handshake;
  a failed handshake may leave fields unknown. Verification failure stops normal
  HTTP collection; do not reconnect insecurely unless explicitly configured.
  Record that override separately from actual verification success. Do not probe
  cipher suites or use shared certificates as an asset-merge rule.
- **Check results:** emit per-check outcomes even when useful metadata is absent;
  retain the collector's operation inventory and policy settings with the scan.

## Surface-specific metadata

All rows inherit the common checks. **Default** means metadata only, where an
anonymous documented operation is available. Authentication requirements vary by
deployment; denied checks remain denied, not a reason to authenticate.

| Surface | Default metadata checks | Version distinctions and optional reads |
|---|---|---|
| MCP | Server implementation identity, negotiated protocol, advertised capabilities; tools with bounded descriptions/input schemas/annotations; resource metadata/templates and URI schemes; prompt metadata. On a 401, anonymous RFC 9728 protected-resource metadata (`/.well-known/oauth-protected-resource`) recording the advertised authorization server(s) | Implementation version is separate from protocol version. Resource content reads are opt-in and limited to reviewed read semantics; listing is sufficient for inventory. Authorization-server URLs are recorded, not followed. Network transports only (Streamable HTTP, legacy SSE); stdio servers are out of scope. |
| A2A | Public agent card at `/.well-known/agent-card.json`, falling back to legacy `/.well-known/agent.json`; provider/interface metadata, advertised skills, protocol support, security requirements | Agent-reported version is separate from protocol version; security declarations are not observed enforcement. Record which card path answered. No automatic retrieval of protected cards or arbitrary linked documents. |
| Ollama | Reported runtime version; model catalog, reported digests, size, and available model metadata | Verify the documented version operation (such as `/api/version`) for supported releases. Model tag/digest is separate from runtime version. Sensitive templates, modelfiles, and system prompts are opt-in. |
| vLLM | Reported server identity/version where available; served model identifiers and exposed metadata | OpenAI-compatible API shape alone does not establish vLLM identity/version. Preserve reported model aliases without guessing backend artifacts. |
| LiteLLM | Gateway identity/version where exposed; model catalog; allowlisted provider/backend and alias metadata | Gateway version and backend versions remain separate. Configuration excerpts are opt-in and secret-redacted; never fetch or retain credentials. |
| Qdrant | Reported service version/build; collection inventory, counts, schema and storage metadata when exposed | Point contents are not default metadata. Any optional bounded point references must preserve collection scope and data minimization. |
| MLflow | Reported server identity/version; experiment and registered-model metadata; model versions, stages/aliases where supported, and sanitized artifact-store references | Registry model version is separate from MLflow version. Artifact contents are not fetched as part of inventory. |
| Jupyter | Reported server/API metadata; authentication outcomes; session metadata and contents listings without file bodies | API version does not imply a particular server/package version. Notebook/file contents require explicit opt-in; redact sensitive session/path metadata. |
| Open WebUI | Reported application identity/version; model inventory and explicitly exposed backend references | Application version is distinct from Ollama or other backends. Configuration excerpts require opt-in and redaction. |
| LangServe | Fingerprint, exposed route/schema metadata and runnable descriptions | An OpenAPI document's application/API version is not automatically the LangServe package version. Bound schemas and avoid treating examples as observed results. |

### M2c long-tail surfaces

Same rules as above. These rows are planning targets; each needs the same
operation inventory and fixtures before it counts as supported.

| Surface | Default metadata checks | Version distinctions and optional reads |
|---|---|---|
| OpenAI-compatible (generic) | API shape fingerprint; served model list; any explicitly reported server identity/version headers or fields | Used only when no specific product is proven; never inferred as vLLM/llama.cpp/TGI from shape alone. No inference, embedding, or completion requests. |
| Ray dashboard | Reported Ray version; cluster/node summary and job/actor listings metadata where anonymously exposed | Job submission and any mutating endpoints are never called. Job entrypoints/env are sensitive: opt-in and redacted. |
| Langflow | Reported version; flow/component inventory metadata where anonymously exposed; auto-login posture | Flow execution and code-validation endpoints are never called. Flow bodies are opt-in and redacted. |
| Flowise | Reported version; chatflow inventory metadata and public-chatflow flags where anonymously exposed | Prediction endpoints are never called. Flow configuration is opt-in and secret-redacted. |
| ChromaDB | Reported version/heartbeat; tenant/database/collection inventory and counts | Collection contents (documents, embeddings) are not default metadata; bounded opt-in only. |

## Per-check result contract

Each result carries a stable `check_id`, target/service reference, scan ID,
collection vantage, operation and sanitized evidence source, timestamp, outcome,
reason, and evidence references. Record metadata values with component attribution.

| Outcome | Meaning |
|---|---|
| `success` | The intended response was validated; individual optional fields may still be unknown |
| `denied` | Evidence indicates an authentication or authorization boundary |
| `unsupported` | A documented/validated response or known supported-version rule establishes the operation is unavailable |
| `failed` | Transport, parsing, ambiguous response, or other failure prevented a reliable result |
| `skipped` | Policy, prerequisite, or configured limit prevented attempting the check; record the reason |

A 404 alone does not prove an operation is unsupported: proxies, base paths, and
routing can produce it. Preserve ambiguity as a failed check with a reason.
Rate limiting is not an authentication denial. An unavailable version field
remains unknown, even if its containing metadata request succeeded.

Check outcome and enumeration coverage are independent. A listing can succeed
but be `truncated`; aggregate `complete`/`partial`/`truncated`/`failed` using the
configured surface and required operations, with unavailable checks visible.
`complete` never means every possible field was available or the host was fully
assessed. Policy-disabled content reads do not make metadata coverage incomplete.

## Comparison readiness (comparisons deferred)

A comparison tool is deferred (see `docs/plans/.future/`). v1 still retains
sufficient structured data in the evidence sidecar for later scope-aware
comparisons of versions, access outcomes, backend references, model digests,
and advertised tool/resource inventories: vantage, check, collection policy,
service identity, and evidence timestamps. A timeout or denied listing is not
proof that previously listed children vanished.

## Acceptance criteria

Each collector must provide a tested operation inventory with supported-release
notes, official documentation references, safe request/response semantics,
version-source precedence, pagination/size limits, and default versus opt-in status.
There is no requirement to discover a version that the service does not expose.

Fixtures must cover success, denial, unsupported/ambiguous responses, rate limits,
malformed versions, proxy banners, conflicting component versions, missing optional
fields, and truncated listings. Common tests cover TLS verification failure and
explicit overrides, scoped redirects, redaction across logs/checkpoints/payloads,
and unchanged service IDs after metadata changes.
Golden exports must preserve check outcomes and evidence attribution even when a
version is unknown. Matrix checks become M2a/M2b/M2c acceptance criteria, not
claims of already-implemented support.
