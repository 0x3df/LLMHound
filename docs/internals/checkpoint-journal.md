# Checkpoint Journal Reference

> **Status: M2a checkpoint journal implemented.** Companion to
> [design](../01-design.md)
> and [graph model](../02-graph-model.md).
> Implemented in `internal/checkpoint`.

The checkpoint journal is an append-only JSON Lines stream (`.journal.jsonl`)
consumed by collectors during scanning to incrementally record targets,
graph nodes, edges, access evidence, and sidecar records.

The journal serves as the crash-resilience and resume foundation for LLMHound:
interrupted scans can resume without rescanning completed work, while preserving
exact original observation provenance. Full CLI resume commands belong to M3.

## Collector Journal Interface

Collectors interact with the `checkpoint.Journal` interface:

```go
type Journal interface {
    Header() Header
    RecordResult(result Result) error
    RecordTarget(record TargetRecord) error
    RecordNode(node emitter.NodeItem) error
    RecordEdge(edge graph.Edge) error
    RecordEvidence(record evidence.Record) error
    Flush() error
    Close() error
}
```

- **`RecordResult(Result)`**: records composite collection results for a target and surface,
  including nodes, edges, sidecar evidence records, coverage outcome, and optional bounded details.
  Automatically records target progress according to the observation's coverage.
- **`RecordTarget(TargetRecord)`**: records target lifecycle events (`started`, `completed`, `partial`, `failed`, `skipped`).
- **`RecordNode(emitter.NodeItem)`**: records an individual OpenGraph node with flat validated properties.
- **`RecordEdge(graph.Edge)`**: records an individual topology or `ObservedAt` edge.
- **`RecordEvidence(evidence.Record)`**: records an individual `.evidence.jsonl` sidecar entry.

## Wire Schema

Each line in the journal is a self-contained JSON object (`JournalEntry`):

| `entry_type` | Payload Field | Purpose |
|---|---|---|
| `header` | `header` | Scan metadata: schema version ("1"), deployment scope, scan ID, collector version, vantage key, created_at UTC |
| `result` | `result` | Composite collector result (target, surface, observation, status, nodes, edges, evidence, error, details) |
| `target` | `target` | Target lifecycle progress (target, surface, status, error, details) |
| `node` | `node` | OpenGraph node item (identity, observation, properties) |
| `edge` | `edge` | Graph edge (kind, start reference, end reference, observation, access, correlation) |
| `evidence` | `evidence` | Sidecar evidence record (check_result, fingerprint, tls, redirect, correlation) |

The first entry in every journal must be `header`.

## Redaction and Bounding Enforcements

To prevent secret leakage and unbounded memory/disk growth, `internal/checkpoint`
enforces the following bounds across all records:

1. **URL Sanitization**: Target and source URLs have userinfo credentials, query strings, and fragments
   stripped via `SanitizeTarget` and `SanitizeURL`.
2. **Secret Redaction**: Any property or detail map key matching `auth`, ending in `token`, or
   containing sensitive substrings (`authorization`, `cookie`, `api_key`, `api-key`, `apikey`,
   `passw`, `secret`, `bearer`, `credential`, `private_key`, `client_secret`) has its value
   masked with `"[REDACTED]"`. The validated secret-presence classification properties
   (`has_exposed_secret`, `secret_types`, `secret_last_confirmed`) are accepted only in their
   canonical shapes (`true`, known detector names, UTC RFC3339 timestamp) and omitted otherwise.
   Free-text strings also strip URL credentials/queries, `Bearer`/`Basic` credentials, and inline
   secret assignments.
3. **String Bounding**: String values exceeding `DefaultMaxStringSize` (4096 bytes) are truncated to 4096 bytes
   with the suffix `"…[truncated]"`.
4. **Entry Size Bound**: Serialized JSON lines exceeding `DefaultMaxEntryBytes` (1 MB) are rejected with
   `ErrEntryTooLarge`.

## Observation Provenance Preservation

Resume and replay must preserve original observation timestamps and identifiers
rather than refreshing stale evidence as newly observed:

- `ObservedAt`: preserved verbatim in UTC RFC3339 format.
- `ScanID` and `EvidenceID`: preserved verbatim.
- `Coverage` (`complete`, `partial`, `failed`, `truncated`) and `CoverageReason`: preserved verbatim.
- `DeploymentScope` and `VantageKey`: restored from the journal header; every observation and evidence record must match them.

## Deterministic Replay and Crash Recovery

`checkpoint.Replay(r io.Reader, opts ...Option)` reconstructs the accumulated scan `*State`:

- **Deterministic Ordering**: Nodes, edges, and evidence records are replayed in deterministic order
  with duplicate deduplication (by Node ID, Edge signature `kind:start:end`, and Evidence ID).
- **Domain Validation**: Replayed nodes, edges, and references are reconstituted through domain constructors
  (`graph.NewNode`, `graph.NewObservedAtEdge`, `graph.NewTopologyEdge`),
  validating kind transitions and non-traversability rules.
- **Native Node Separation**: Replayed edges touching existing native nodes (any kind) preserve
  `TouchesNative() == true` and empty `SourceKind()`, ensuring safe segregation between owned and linking payloads.
- **Completion Semantics**: A surface counts as completed only when its record has status `completed`
  and a valid observation with `complete` coverage whose surface matches the record. `partial`/`truncated`
  coverage, a nil observation, or a surface-less record never count, and an explicit status never overrides
  observed coverage. `State.IsCompleted(target, surface)` reports this per surface; `State.CompletedTargets()`
  means only "every recorded surface is completed". The journal records what happened and cannot attest
  surfaces that were never recorded, so the M3 resume command must derive the expected surface set from
  config/targets and check `IsCompleted` per surface instead of skipping targets via `CompletedTargets()`.
- **Crash Recovery**: If a scan process terminates abruptly mid-write, the incomplete trailing line at EOF
  is detected as `*TruncatedEntryError`. Replay preserves all successfully committed records prior to the crash.
