# Scan coverage — live CLI vs unit tests

Companion to the [design](../01-design.md) M2a vertical
slice. Records which acceptance behaviors were exercised through the product
CLI against disposable loopback fixtures versus covered only by package unit
tests. Library-only collector tests do **not** prove CLI integration.

## Implemented in this slice

| Capability | Where |
|---|---|
| Data-driven discovery fingerprints (all 15 surfaces; `openai_compatible` fallback guarded per host:port) | `internal/discovery` |
| Checkpoint journal writers, torn-tail repair + deterministic replay | `internal/checkpoint` |
| Offline `llmhound plan` (targets × allowlisted checks) | `cmd/llmhound`, `internal/scanner` |
| `llmhound scan` & `llmhound resume` orchestration → journal → OpenGraph + evidence + content | `cmd/llmhound`, `internal/scanner` |
| Bounded D3 content tier + `0600` `.content.jsonl` isolation | `internal/content`, collectors |
| High-precision D4 secret detection (`private_key`, `github_token`, `aws_access_key`) + `[secret:<type>]` redaction | `internal/secrets`, `internal/content`, collectors |
| All 15 collectors (Jupyter, MCP, Ollama, A2A, vLLM, Qdrant, LiteLLM, MLflow, Open WebUI, LangServe, Generic OpenAI-compatible, Ray, Langflow, Flowise, ChromaDB) | `internal/collectors/*` |
| Mapping-file attachment to an existing native node (any kind) with `mapping_source` + source_kind-free linking payload | `internal/correlate`, `internal/emitter`, scanner tests |
| Opt-in `CanExecuteOn` path-qualification rule engine (`jupyter-auth-disabled`, `ray-anonymous-jobs`, `langflow-unauthenticated-exec`) | `internal/rules`, `extension/rules` |
| BloodHound CE API client, `v9.7.1` gate, M0 Q5 two-step upload with read-only Cypher pre-flight, saved-query import (`llmhound upload`) | `internal/bloodhound`, `cmd/llmhound` |
| All 15 shipped BloodHound CE saved queries (`P1`–`P8`, `I1`–`I7`) and generator | `internal/savedsearch`, `extension/saved_searches/`, `tools/gensearches` |

## Driven live (product CLI + loopback fixtures)

Exercised by `cmd/llmhound` tests (`TestScanCLIEndToEndLoopbackFixtures`,
`TestScanCLIM2bCohortLoopbackFixtures`,
`TestScanCLID5D6CohortLoopbackFixtures`,
`TestResumeCLI`,
`TestUploadCLIWithMockCE`,
`TestUploadValidationAndPlanWritesNoArtifacts`,
`TestPlanMakesNoDNSQueriesOrTargetConnections`) and matching
`internal/scanner` end-to-end tests against `httptest` fixtures:

- All 15 surfaces exercised on loopback via CLI with `--discovery-file` port remap
- `resume` skips already-completed `(target, surface)` pairs with zero extra traffic after repairing a torn journal tail
- Mock BloodHound CE integration testing `--validate-only`, `--register-schema --enable-rules-schema`, two-step upload with pre-flight filtering of missing/stub native nodes, `--import-queries`, and CE version mismatch rejection
- Emitted base payload `source_kind: LLMHound`, expected node/edge kinds
- Evidence sidecar check / fingerprint / correlation record types and `detected_exposures`
- Restricted `.content.jsonl` (mode `0600`) across content-capable surfaces with zero body or secret leakage into base payload or evidence sidecar
- Checkpoint journal file written beside payload artifacts
- Offline `plan` prints all 15 surfaces/checks and creates no artifacts / no DNS / no connections
- Denied Ollama (HTTP 401) path via CLI discovery remap (emits denied evidence sidecar and fails closed)

## Unit / package coverage only (not CLI-live in this note)

- Per-collector check matrices, pagination bounds, TLS evidence, redirect scope
  (`internal/collectors/*` tests)
- Journal concurrency, sanitize, resume-semantics helpers (`internal/checkpoint`)
- Fingerprint matcher edge cases (`internal/discovery`)
- Path-qualification `CanExecuteOn` rule evaluation (`TestScanner_PathQualificationRules` in `internal/scanner`, `internal/rules`, `extension/rules`)
- Mapping-file native-node correlation + linking payload without `source_kind`
  (`TestScanner_MappedTargetAttachesToNativeNodeViaLinkingPayload` — library scan path, not
  `cmd/llmhound execute`)
- Unreachable-port failed coverage and denied `partial` coverage reasons
  (`TestScanner_MixedTargetsAndHonestCoverage`)
- Attachment of a mapped target to a native node of a non-`Computer` kind (library path)

## Remaining capability gaps (out of this bounded task)

- Credential-driven enumeration (M4)
- Live lab UI verification of `CanExecuteOn` rendering in BloodHound CE UI
- TCP-first port sweep (scan probes each configured definition once with its
  probe paths and matcher; unmatched or unreachable surfaces are journaled as
  failed coverage without collector requests, matched surfaces are collected)
- ZIP-streaming emission for very large scans
