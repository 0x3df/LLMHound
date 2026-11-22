# Collector capability matrix

**Status: all 15 M2a/M2b/M2c collectors (Jupyter, MCP, Ollama, A2A, vLLM, Qdrant, LiteLLM, MLflow, Open WebUI, LangServe, Generic OpenAI-compatible, Ray, Langflow, Flowise, and ChromaDB) are implemented and wired
through `llmhound plan` / `llmhound scan` / `llmhound resume` (`internal/scanner`).**
This is the v1 collection contract for the [design](01-design.md) and
[graph model](02-graph-model.md), not a claim that every product release exposes
every field anonymously. Exact operations and supported releases must be verified
against official product/protocol documentation and recorded in collector tests.
Live CLI coverage vs package-only tests: [scan coverage](internals/scan-coverage.md);
per-collector behavior: [`collectors/`](collectors/).
Default-on, bounded content-tier reads (Ollama, Jupyter, MCP, Qdrant, A2A, LiteLLM,
MLflow, Open WebUI, LangServe, Ray, Langflow, Flowise, ChromaDB) are
implemented and isolated in `<prefix>.content.jsonl` (mode `0600`);
high-precision secret detection over those bodies is implemented in
`internal/secrets` (`private_key`, `github_token`, `aws_access_key`; see the
[implementation status](02-graph-model.md#implementation-status)).

## Default collection policy

All checks are anonymous, bounded, allowlisted, read-only operations. Metadata
checks are the baseline; content-tier reads (below) are on by default where one
read returns them. Validate operation semantics, not just HTTP method: some read-only APIs use POST,
and GET alone does not guarantee a safe operation. Transport initialization may
establish a protocol session; it must not initiate application workloads.
Stop at authentication boundaries. No credentials are sent to scanned services.

Existing content reads (the **content tier**: prompts, configuration, file and
flow bodies, bounded samples) are on by default when a single allowlisted
anonymous read returns them. They are bounded, stored only in the restricted
content file, and can be disabled per surface; see
[Content and secrets](02-graph-model.md#content-and-secrets). Metadata collection
must remain useful without them. Exposed secrets are recorded as a boolean
only, via high-precision detectors, and never stored, used, or validated.

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
- **Access posture:** record the outcome of each metadata/listing operation,
  tagged with the configured `vantage_key`. Succeeded operations populate
  `anon_operations`; other outcomes go to the sidecar. Listing, metadata
  retrieval, and content-tier reads are separate observations; an HTTP 200
  login page is not a successful listing.
- **Execution surface and auth posture:** classify each service's
  `exec_surface` and `auth_advertised`/`auth_observed` as defined in the
  [property contract](02-graph-model.md#property-contract), with the basis
  (`observed`, `declared`, or `inferred`). Classification uses only allowlisted
  reads; it never invokes the capability.
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

All rows inherit the common checks. **Default metadata checks** are the
baseline, where an anonymous documented operation is available; **content-tier
reads** follow the content policy above. Authentication requirements vary by
deployment; denied checks remain denied, not a reason to authenticate.

| Surface | Default metadata checks | Version distinctions and content-tier reads |
|---|---|---|
| MCP | Server implementation identity, negotiated protocol, advertised capabilities; tools with bounded descriptions/input schemas/annotations; resource metadata/templates and URI schemes; prompt metadata. On a 401, anonymous RFC 9728 protected-resource metadata (`/.well-known/oauth-protected-resource`) recording the advertised authorization server(s) | Implementation version is separate from protocol version. Text resource bodies (`mcp_resources_read`, content tier) are read by default into `.content.jsonl` within `content.*` bounds and skip binary MIME types; `tools` are never invoked. Authorization-server URLs are recorded, not followed. Network transports only (Streamable HTTP, legacy SSE); stdio servers are out of scope. |
| A2A | Public agent card at `/.well-known/agent-card.json`, falling back to legacy `/.well-known/agent.json`; provider/interface metadata, advertised skills, protocol support, security requirements | Agent-reported version is separate from protocol version; security declarations are not observed enforcement. Record which card path answered. Retrieved card JSON is recorded in `.content.jsonl` under `content.*` bounds without an extra request. No automatic retrieval of protected cards or arbitrary linked documents. |
| Ollama | Reported runtime version; model catalog, reported digests, size, and available model metadata | Verify the documented version operation (such as `/api/version`) for supported releases. Model tag/digest is separate from runtime version. Templates, modelfiles, and system prompts are read by default (`ollama_show`, content tier) via `/api/show` into `.content.jsonl` within `content.*` bounds. |
| vLLM | Reported server identity/version (`GET /version`); served model identifiers and aliases (`GET /v1/models`) when vLLM-specific evidence is present | OpenAI-compatible API shape alone does not establish vLLM identity/version; generic servers without vLLM evidence fail closed. Preserve reported model aliases without guessing backend artifacts. |
| LiteLLM | Gateway identity/version where exposed; model catalog; allowlisted provider/backend and alias metadata | Gateway version and backend versions remain separate. Configuration is a content-tier read; a high-precision secret match sets only a presence flag; the value is discarded. |
| Qdrant | Reported service version and commit (`GET /`); collection inventory (`GET /collections`), schema/counts (`GET /collections/<name>`), and snapshot listings (`GET /snapshots`) when exposed | Point payloads (`qdrant_points_sample` via `POST /collections/<name>/points/scroll` with `with_vector: false`) are content-tier bounded samples (default 5 per collection) into `.content.jsonl` that preserve collection scope; vectors are never fetched. |
| MLflow | Reported server identity/version; experiment and registered-model metadata; model versions, stages/aliases where supported, and sanitized artifact-store references | Registry model version is separate from MLflow version. Artifact listings are inventory; small text artifacts (MLmodel, requirements, parameters) are content-tier reads; model weights are never fetched. |
| Jupyter | Reported server/API metadata; authentication outcomes; session metadata and contents listings without file bodies | API version does not imply a particular server/package version. Non-binary notebook and file bodies are read by default (`jupyter_file_content`, content tier) into `.content.jsonl` within `content.*` bounds. |
| Open WebUI | Reported application identity/version; model inventory and explicitly exposed backend references | Application version is distinct from Ollama or other backends. Configuration is a content-tier read. |
| LangServe | Fingerprint, exposed route/schema metadata and runnable descriptions | An OpenAPI document's application/API version is not automatically the LangServe package version. Bound schemas (`langserve_schemas`) and capture JSON schema bodies into `.content.jsonl`; avoid treating examples as observed results. |

### Long-tail surfaces

Same rules as above. All five long-tail collectors are implemented with per-surface
operation inventories and fixtures.

| Surface | Default metadata checks | Version distinctions and content-tier reads |
|---|---|---|
| OpenAI-compatible (generic) | API shape fingerprint; served model list; any explicitly reported server identity/version headers or fields | Used only when no specific product is proven; never inferred as vLLM/llama.cpp/TGI from shape alone. No inference, embedding, or completion requests. |
| Ray dashboard | Reported Ray version; cluster/node summary and job/actor listings metadata where anonymously exposed | Job submission and any mutating endpoints are never called. Job entrypoints and environment are content-tier reads; a high-precision secret match sets only a presence flag. |
| Langflow | Reported version; flow/component inventory metadata where anonymously exposed; auto-login posture | Flow execution and code-validation endpoints are never called. Flow bodies are content-tier reads. |
| Flowise | Reported version; chatflow inventory metadata and public-chatflow flags where anonymously exposed | Prediction endpoints are never called. Flow configuration is a content-tier read. |
| ChromaDB | Reported version/heartbeat; tenant/database/collection inventory and counts | Collection documents are content-tier bounded samples; embeddings are never fetched. |

## Path-relevant classification

The project exists to answer tier-0 pathing questions, so collectors must
extract the facts that matter for them (the [min-max
principle](02-graph-model.md#property-contract)). This table lists, per surface,
what to classify beyond identity and version. Values are not evidence of
exploitability; the **Opt-in rule** column notes surfaces with a shipped rule under the
[path-qualification bar](02-graph-model.md#path-qualification-traversable-edges).
All rules are disabled by default and require explicit opt-in in `llmhound.yaml`.

| Surface | Execution surface to classify | Other path-relevant facts | Opt-in rule |
|---|---|---|---|
| MCP | `tool_invocation` (declared); per-tool `capability_hint` (planned) | Transport and auth model, OAuth authorization-server references, resource URI schemes, whether tools list anonymously | No (advertisement is not evidence) |
| A2A | `tool_invocation` (declared) from skills/interfaces | Advertised security schemes, linked agents and interfaces (recorded, not followed) | No |
| Ollama | `model_mutation` (pull/delete exposed anonymously is not host execution) | Model catalog, digests, bind/exposure hints, version | No |
| vLLM | none expected | Served models, aliases, version | No |
| LiteLLM | `workflow_exec` only if exposed | Backend/provider references (redacted), key-management endpoints listed in the OpenAPI document (never called), version | No |
| Qdrant | none expected | Collections, counts, storage/snapshot endpoints present, API-key requirement | No |
| MLflow | `model_mutation` | Artifact-store references, registry stages, version | No (revisit with documented semantics) |
| Jupyter | `code_kernel`, `terminal` | Whether the API requires a token, kernel/session listings, contents listing, version | Yes (`jupyter-auth-disabled`, opt-in) |
| Open WebUI | none expected | Backend references, signup/auth settings exposed, version | No |
| LangServe | `code_eval` only if documented for the route | Routes, schemas, playground exposure | No |
| Ray dashboard | `job_submit` | Cluster/node summary, job listing, version | Yes (`ray-anonymous-jobs`, opt-in) |
| Langflow | `workflow_exec`, `code_eval` | Auto-login posture, version | Yes (`langflow-unauthenticated-exec`, opt-in) |
| Flowise | `workflow_exec` | Public-chatflow flags, version | Revisit |
| ChromaDB | none expected | Tenants/databases/collections, auth provider | No |
| OpenAI-compatible | none expected | Served models, identity headers | No |

## Per-check result contract

Each result carries a stable `check_id`, target/service reference, scan ID,
`vantage_key`, operation and sanitized evidence source, timestamp, outcome,
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

## Downstream use

Comparison and reconciliation are handled downstream by the normalization
program (and a possible `llmhound diff`, see [future ideas](future-ideas.md)). The
sidecar retains the vantage key, check, collection policy, service identity,
and timestamps they need. A timeout or denied listing is not proof that
previously listed children vanished.

## Acceptance criteria

Each collector must provide a tested operation inventory with supported-release
notes, official documentation references, safe request/response semantics,
version-source precedence, pagination/size limits, and metadata versus
content-tier status.
There is no requirement to discover a version that the service does not expose.

Fixtures must cover success, denial, unsupported/ambiguous responses, rate limits,
malformed versions, proxy banners, conflicting component versions, missing optional
fields, and truncated listings. Common tests cover TLS verification failure and
explicit overrides, scoped redirects, secret values absent from logs,
checkpoints, payloads, sidecar, and content file, secret detectors proven
against true-positive and look-alike-negative corpora with zero false
positives, and unchanged service IDs after metadata changes.
Golden exports must preserve check outcomes and evidence attribution even when a
version is unknown.
