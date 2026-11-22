# Development guide

Everything needed to build, test, and change LLMHound. For architecture read the
[design](../01-design.md); for what to build next read the [roadmap](../06-roadmap.md).

## Prerequisites

- Go 1.27.4 or newer (pinned in `go.mod`; earlier 1.27 patch releases carry GO-2026-6859).
- Docker with the Compose plugin, only for the [BloodHound CE lab](../../lab/README.md).
- No service credentials and no production network are needed for any test.

## Build and verify

```bash
CGO_ENABLED=0 go build -o llmhound ./cmd/llmhound   # single static binary
gofmt -l .                                          # must print nothing
go vet ./...
go test -race ./...                                 # includes ./docs
```

CI runs these plus `go build ./...`, a Windows cross-build and `vet`, pinned
`staticcheck` (v0.8.2) and `govulncheck` (v1.10.0) for both the host and
`GOOS=windows`, and `go test ./...` on a Windows runner. A change is not done
until all pass:

```bash
go run honnef.co/go/tools/cmd/staticcheck@v0.8.2 ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.10.0 ./...
GOOS=windows CGO_ENABLED=0 go build ./... && GOOS=windows go vet ./...
```

Unstamped builds report `dev+<commit>` (or the module pseudo-version) from build
info, so journals and evidence are always attributable. Release builds stamp the
tag: `go build -ldflags "-X main.version=v1.0.0" ./cmd/llmhound`.

| Command | Purpose |
|---|---|
| `go test ./docs` | Docs integrity: links, anchors, the docs index, `legacy/docs/` ARCHIVED banners, removed concepts, leftover conflict markers |
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
loopback only and reproduces the [CE compatibility checks](../05-ce-compatibility.md). Use it to
verify any claim about CE behavior: `run-m0-checks.sh` covers Q1–Q10, `run-r-checks.sh` covers
follow-ups R1–R9 against the real extension schema, `run-d2-checks.sh` tests saved searches, and
`run-m3-gate.sh` verifies `llmhound upload` (`--validate-only`, schema, pre-flight, and queries).

```bash
cd lab && ./scripts/lab-up.sh && ./scripts/run-m0-checks.sh   # see lab/README.md
./scripts/run-r-checks.sh                                    # R1–R9, ~40 min (ingest is slow)
./scripts/run-d2-checks.sh                                   # saved searches on emitted scan data
./scripts/run-m3-gate.sh                                     # adapter gate, pre-flight & upload CLI
```

## Continuous integration

[`.github/workflows/go.yml`](../../.github/workflows/go.yml) runs on `pull_request` events
(opened, synchronized, reopened) against the PR's merge commit, and on every push to `QA` and
`main` so a commit that bypasses a PR is still validated. It has no secrets, no write
permissions, no path filters, and no network collection.

- `actions/setup-go` reads the version from `go.mod`; a setup failure is a failed check.
- Formatting (`gofmt -l`), `go test -race ./...`, `go vet ./...`, `go build ./...`,
  `CGO_ENABLED=0 go build ./...`, the Windows cross-build/vet, `staticcheck`, and
  `govulncheck` must all succeed, and a separate `windows-latest` job runs `go test ./...`
  because Windows is the production collection platform. No step runs the scanner.
- A product PR needs an actual successful Go validation job on its latest revision. An absent
  run or a skipped job is **not** green.

If a PR shows no run: confirm the workflow is present in the merge ref, the PR is mergeable
(merge conflicts block `pull_request` runs), Actions is enabled, and any required approval was
granted. Closing and reopening the same PR re-emits the event without changing its head. Never
reinterpret missing checks as success or widen token permissions to bypass them.

[`.github/workflows/release.yml`](../../.github/workflows/release.yml) runs on a pushed `v*`
tag: it re-verifies the tagged commit, builds version-stamped `CGO_ENABLED=0 -trimpath`
binaries (Windows amd64, Linux amd64/arm64, macOS arm64), and publishes them with
`SHA256SUMS` as a GitHub release. Cut a release with
`git tag -a v1.0.0 -m v1.0.0 && git push origin v1.0.0`.

History: the original bootstrap-era notes are archived in
[`legacy/docs/go-ci-bootstrap-notes.md`](../../legacy/docs/go-ci-bootstrap-notes.md).
