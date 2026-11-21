# Scan coverage — live CLI vs unit tests

Companion to the [design](../01-design.md) M2a vertical
slice. Records which acceptance behaviors were exercised through the product
CLI against disposable loopback fixtures versus covered only by package unit
tests. Library-only collector tests do **not** prove CLI integration.

## Implemented in this slice

| Capability | Where |
|---|---|
| Data-driven discovery fingerprints (Jupyter / MCP / Ollama) | `internal/discovery` |
| Checkpoint journal writers + deterministic replay | `internal/checkpoint` |
| Offline `llmhound plan` (targets × allowlisted checks) | `cmd/llmhound`, `internal/scanner` |
| `llmhound scan` orchestration → journal → OpenGraph + evidence | `cmd/llmhound`, `internal/scanner` |
| Jupyter / MCP / Ollama collectors (anonymous, read-only defaults) | `internal/collectors/{jupyter,mcp,ollama}` |
| Mapping-file attachment to an existing native node (any kind) + source_kind-free linking payload | `internal/correlate`, `internal/emitter`, scanner tests |

## Driven live (product CLI + loopback fixtures)

Exercised by `cmd/llmhound` tests (`TestScanCLIEndToEndLoopbackFixtures`,
`TestUploadStillUnimplementedAndPlanWritesNoArtifacts`,
`TestPlanMakesNoDNSQueriesOrTargetConnections`) and matching
`internal/scanner` end-to-end tests against `httptest` fixtures:

- Mixed Jupyter + MCP + Ollama on loopback with `--discovery-file` port remap
- Emitted base payload `source_kind: LLMHound`, expected node/edge kinds
- Evidence sidecar check / fingerprint / correlation record types
- Checkpoint journal file written beside payload artifacts
- Offline `plan` prints surfaces/checks and creates no artifacts / no DNS / no connections
- Denied Ollama (HTTP 401) path via CLI discovery remap (honest auth-boundary coverage detailed in scanner package tests)
- `upload` remains an honest not-implemented stub

## Unit / package coverage only (not CLI-live in this note)

- Per-collector check matrices, pagination bounds, TLS evidence, redirect scope
  (`internal/collectors/*` tests)
- Journal concurrency, sanitize, resume-semantics helpers (`internal/checkpoint`)
- Fingerprint matcher edge cases (`internal/discovery`)
- Mapping-file Computer correlation + linking payload without `source_kind`
  (`TestScanner_ComputerCorrelationAndLinkingPayload` — library scan path, not
  `cmd/llmhound execute`)
- Unreachable-port failed coverage and denied `partial` coverage reasons
  (`TestScanner_MixedTargetsAndHonestCoverage`)
- Attachment of a mapped target to a native node of a non-`Computer` kind (library path)

## Remaining capability gaps (out of this bounded task)

- Full `llmhound resume` command and interrupted-scan pickup (M3)
- CE API client, extension upload, saved-query import, CE Computer lookup (M3)
- M2b/M2c collectors (A2A, vLLM, LiteLLM, Qdrant, MLflow, Open WebUI, LangServe, long tail)
- Credential-driven enumeration (M4)
- TCP-first port sweep (scan probes each configured definition once with its
  probe paths and matcher; unmatched or unreachable surfaces are journaled as
  failed coverage without collector requests, matched surfaces are collected)
- ZIP-streaming emission for very large scans
