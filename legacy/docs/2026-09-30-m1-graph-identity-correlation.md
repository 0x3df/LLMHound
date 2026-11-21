> **ARCHIVED.** M1 implementation plan for graph identity and correlation. Completed, and its correlation design (AD-suffix matching against a verified inventory) has been superseded. Not current. See [`legacy/README.md`](../README.md) and the live docs under [`docs/`](../../docs/README.md).

# M1 Graph Identity and Correlation Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement the approved design's standalone graph primitives and honest, input-only Computer correlation.

**Architecture:** `internal/graph` owns immutable, scoped identities, the central logical-to-CE kind mapping, typed references, and non-traversable observation edges. `internal/correlate` consumes explicit mappings and an externally verified Computer inventory; it never performs DNS or CE lookup. M0's native-node tagging and silent endpoint-resolution failures require native references to remain outside source-owned payloads and unverified matches to fall back.

**Tech Stack:** Go (`github.com/0x3df/LLMHound`), standard library, table-driven unit tests. No dependency on CLI/config/targets work.

## Boundaries and approved decisions

This implements the existing design, not a new collector architecture. No emitter, extension JSON, evidence writer, CLI/config loader, collector, network request, reverse DNS, CE API client, cleanup, or reconciliation is added.

- Identity v1 is SHA-256 of a JSON string tuple containing version, source, deployment scope, concrete logical kind and stable key fields. Hex IDs are upper-case for M0 CE behavior.
- HTTP(S) endpoint normalization includes DNS case/root dot, IP spelling, effective numeric port, root-path equivalence, and percent-escape normalization. Non-root trailing slashes, repeated slashes, dot segments, escaped separators and path case stay distinct. Unicode DNS input requires an ASCII A-label. Invalid authorities, userinfo and fragments fail closed. Query-bearing endpoints require an explicit non-secret instance key; queries are excluded from identity and never retained.
- Child keys and scoped vantage keys remain exact/case-sensitive. Mutable observation fields never enter identity. IP targets and DNS targets remain separate.
- Explicit mappings have precedence, but mapping destinations must appear in the caller's verified Computer inventory. An invalid, unverified or ambiguous mapping does not silently fall through to a weaker rule.
- AD-suffix matching requires an explicitly enabled M0-supported property matcher (`name`, exact upper-case FQDN). Only a unique existing inventory record permits a property reference. No inventory means no proven match, even if CE could accept the matcher. No reverse DNS or lookup is invented.
- Native references preserve supplied IDs verbatim. They cannot become source-owned node identities. Native-touching edges explicitly require a sourceless linking payload, per M0 Q5.
- Access evidence requires a validated successful anonymous enumeration/resource-read operation, exact target, vantage and original provenance. TCP probes, declarations, denied/failed checks and broad access assumptions are insufficient. `ObservedAt` never creates `RunsOn`; that kind remains reserved and non-traversable.
- Provenance and coverage remain explicit data; there are no automatic timestamp refreshes or deletion APIs.

## Task 1: Endpoint and identity primitives

**Create:** `go.mod`, `internal/graph/kinds.go`, `internal/graph/identity.go`, `internal/graph/endpoint.go`.
**Tests:** `internal/graph/identity_test.go`, `internal/graph/endpoint_test.go`.

1. Write table-driven tests for endpoint equivalence/separation, invalid input, versioned identity golden values, exact resource keys, ownership, vantage and scope separation.
2. Run `go test ./internal/graph`; observe missing-feature failure.
3. Implement canonical target/endpoint values and immutable identity constructors. Source-owned constructors reject Computer/umbrella/unknown kinds. Add central `LLMHound_<Kind>` mapping.
4. Run `go test ./internal/graph`; require PASS. Commit this tested slice.

## Task 2: Typed nodes, references and observation edges

**Create:** `internal/graph/model.go`, `internal/graph/observation.go`.
**Tests:** `internal/graph/model_test.go`.

1. Write tests for owned node kinds, native-ID preservation, linking-payload segregation, every edge's non-traversability, correct endpoint types and access direction, TCP/declaration/negative-result rejection, unchanged provenance and independent check/coverage values.
2. Run `go test ./internal/graph`; observe missing-feature failure.
3. Implement typed reference/node/edge constructors and explicit observation validation; keep `RunsOn` reserved and reject automatic placement. Return original times without refreshing them.
4. Run `go test ./internal/graph`; require PASS. Commit this tested slice.

## Task 3: Input-only Computer correlation

**Create:** `internal/correlate/correlate.go`.
**Tests:** `internal/correlate/correlate_test.go`.

1. Write tests for exact verified mapping, mapping precedence, equivalent target spellings, duplicate/ambiguous mappings and Computers, unverified destinations, suffix boundaries, name matcher casing, capability-disabled fallback, IP-only behavior, malformed configuration and rescan correlation without changed service identity or native ownership.
2. Run `go test ./internal/correlate`; observe missing-feature failure.
3. Implement deterministic resolution and fallback decisions with match method/value/confidence, candidate IDs and honest fallback reasons. Return only a fallback owned identity or a verified native reference.
4. Run `go test ./internal/graph ./internal/correlate`; require PASS. Commit this tested slice.

## Task 4: Accurate reference documentation and validation

**Modify:** `docs/reference/graph-model.md` and, only for broadly useful pointers, `AGENTS.md`.

1. Replace obsolete pre-M0 wording only where it affects this implemented contract. Document canonicalization, caller-supplied verification, native-link segregation and preserved lifecycle provenance. Do not claim the emitter or other M1 portions are implemented.
2. Run `gofmt -l internal/graph internal/correlate`, `go test -race ./...`, `go vet ./...`, `go build ./...`, and focused coverage inspection. No network/lab mutations.
3. Review diff and check inbox. Commit docs and any independently tested corrections.
4. Report committed handoff to firstmate. Do not push; firstmate starts no-mistakes, with every resulting PR targeting QA.
