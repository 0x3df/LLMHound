# Development guide

Everything needed to build, test, and change LLMHound. For architecture read the
[design](../01-design.md); for what to build next read the [roadmap](../06-roadmap.md).

## Prerequisites

- Go 1.27 or newer (the toolchain pinned in `go.mod`; developed with 1.27.1).
- Docker with the Compose plugin, only for the [BloodHound CE lab](../../lab/README.md).
- No service credentials and no production network are needed for any test.

## Build and verify

```bash
CGO_ENABLED=0 go build -o llmhound ./cmd/llmhound   # single static binary
gofmt -l .                                          # must print nothing
go vet ./...
go test -race ./...                                 # includes ./docs
```

CI runs exactly these (plus `go build ./...`). A change is not done until all pass.

| Command | Purpose |
|---|---|
| `go test ./docs` | Docs integrity: links, anchors, the docs index, leftover conflict markers |
| `go test ./internal/emitter` | Golden payloads; regenerate deliberately with `UPDATE_GOLDEN=1 go test ./internal/emitter -run TestGoldenEmission` and review the diff, since goldens define the emitted contract |
| `go test ./extension` | The extension schema agrees with `internal/graph` kinds |

## Workflow

- `QA` is the integration branch; PRs target `QA`, not `main`.
- Work in small, reviewable steps on a topic branch. Do not force-push or rebase shared branches.
- **Behavior and docs change together.** Update the affected rows of the
  [implementation status](../02-graph-model.md#implementation-status) and the owning doc in the
  same change ([where each rule lives](../README.md)).
- Commit messages explain *why*; the body lists behavior changes.

## The CE lab

[`lab/`](../../lab/README.md) is a pinned BloodHound CE 9.7.1 + PostgreSQL 18 lab that binds to
loopback only and reproduces the [M0 findings](../05-ce-compatibility.md). Use it to verify any
claim about CE behavior. `run-m0-checks.sh` covers Q1–Q10 and `run-r-checks.sh` covers the
tier-0 follow-ups R1–R9 against the real extension schema. The adapter gate (M3) re-runs both
against a candidate CE release.

```bash
cd lab && ./scripts/lab-up.sh && ./scripts/run-m0-checks.sh   # see lab/README.md
./scripts/run-r-checks.sh                                    # R1–R9, ~40 min (ingest is slow)
./scripts/run-d2-checks.sh                                   # saved searches on emitted scan data
```

## Continuous integration

[`.github/workflows/go.yml`](../../.github/workflows/go.yml) runs on `pull_request` events
(opened, synchronized, reopened) against the PR's merge commit. It has no secrets, no write
permissions, no path filters, and no network collection.

- `actions/setup-go` reads the version from `go.mod`; a setup failure is a failed check.
- Formatting (`gofmt -l`), `go test -race ./...`, `go vet ./...`, `go build ./...`, and
  `CGO_ENABLED=0 go build ./...` must all succeed. Neither build step runs the scanner.
- A product PR needs an actual successful Go validation job on its latest revision. An absent
  run or a skipped job is **not** green.

If a PR shows no run: confirm the workflow is present in the merge ref, the PR is mergeable
(merge conflicts block `pull_request` runs), Actions is enabled, and any required approval was
granted. Closing and reopening the same PR re-emits the event without changing its head. Never
reinterpret missing checks as success or widen token permissions to bypass them.

History: the original bootstrap-era notes are archived in
[`legacy/docs/go-ci-bootstrap-notes.md`](../../legacy/docs/go-ci-bootstrap-notes.md).
