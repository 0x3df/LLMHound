# Legacy

Retired material, kept for history and never built. Nothing here is current; for live
documentation start at [`docs/`](../docs/README.md).

## What is here

| Path | What it was | Why it was retired |
|---|---|---|
| [`docs/2026-09-30-m1-cli-inputs.md`](docs/2026-09-30-m1-cli-inputs.md) | M1 implementation plan: CLI and target inputs | Completed |
| [`docs/2026-09-30-m1-graph-identity-correlation.md`](docs/2026-09-30-m1-graph-identity-correlation.md) | M1 implementation plan: graph identity and correlation | Completed; its AD-suffix correlation design is superseded |
| [`docs/go-ci-bootstrap-notes.md`](docs/go-ci-bootstrap-notes.md) | CI notes from when the repo had no Go module and two PRs were open | The module exists and those PRs merged; replaced by the [development guide](../docs/guides/development.md) |
| [`code/correlate-suffix-matching/`](code/correlate-suffix-matching/) | The original `internal/correlate` package: mapping file plus AD-suffix property matching against a caller-supplied verified Computer inventory, with its tests | Attribution moved to the separate normalization program; correlation is now mapping-file only and attaches to any native kind ([decision 8](../docs/07-decisions.md)) |

Archived Go files start with `//go:build ignore`, so `go build`, `go vet`, and `go test`
skip them.

## The earlier model, in full

The first implementation (M0 through M2a) followed a model with a `CollectionVantage` node,
`UnauthenticatedAccess` and `PublicAccess` edges, and AD-suffix correlation. The complete tree
at that point is preserved by the git tag `legacy/earlier-model-m2a`:

```bash
git show legacy/earlier-model-m2a:docs/reference/graph-model.md   # the earlier graph model
git worktree add ../llmhound-earlier legacy/earlier-model-m2a      # browse or build it
```

## What replaced it

See the [decision log](../docs/07-decisions.md): anonymous access became flat service
properties (decision 11), attachment became mapping-file only (8, 9), and the content and
secrets handling was added (15).
