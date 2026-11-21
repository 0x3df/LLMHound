> **ARCHIVED.** Bootstrap-era CI notes, written when the repository had no Go module and while two product PRs were open. The module exists and those PRs have merged, so the bootstrap and PR-specific sections no longer apply. The current guide is [`docs/guides/development.md`](../../docs/guides/development.md); see [`legacy/README.md`](../README.md).

# Go CI for QA pull requests

[`.github/workflows/go.yml`](../../.github/workflows/go.yml) runs on normal
`pull_request` events: opened, synchronized (head updated), and reopened.
There are no path filters, secrets, write permissions, or network collection
steps. It uses GitHub-hosted Ubuntu runners and checks out the PR's merge
commit, testing the proposed result against its current base branch.

## Bootstrap versus product evidence

The M0-only base has no Go module. The **Detect Go module (bootstrap only if
absent)** job succeeds with an explicit bootstrap-only summary; **Go format,
race tests, vet, build** is **skipped**, not passed. That outcome validates
workflow bootstrap, not a Go product. Go sources or nested modules without a
root `go.mod` cause detection to fail rather than silently bypass checks.

When the checked-out PR has a root `go.mod`, Go validation is required:

- `actions/setup-go` reads `go.mod` (`toolchain` when present, otherwise `go`).
  No hard-coded Go version or substitute module is used. Download/setup
  failure is a failed check, not an exemption.
- Formatting checks all tracked `*.go` files with `gofmt -l`, without rewriting
  files, and fails if any need formatting.
- `go test -race ./...`, `go vet ./...`, `go build ./...`, and
  `CGO_ENABLED=0 go build ./...` must succeed. The latter checks compilation
  without cgo; neither build step runs the scanner.

A product PR needs an actual successful Go validation job for its latest
revision. An absent run, skipped job, or successful bootstrap job is **not**
product CI green. This workflow does not replace product review or other
validation gates, and it does not automate merging.

## Trigger checks on already-open QA PRs

Landing a workflow on QA does not itself emit a new `pull_request` event for
already-open PRs. After the workflow lands, the merge authority can use its
normal authenticated `gh-axi` session (not a workflow's `GITHUB_TOKEN`) to
**close and reopen the same PR without deleting its branch**. Reopening is a
supported trigger and preserves its head commit, code, reviews, and URL. It
briefly changes the PR's state; coordinate with its active pipeline monitor.
Do not run `update-branch`, rebase, force-push, add empty commits, or restart
product validation as a substitute.

For the existing CLI and graph PRs, respectively (run from this repository;
`gh-axi pr` takes a numeric identifier, extracted here from each full URL):

```bash
for pr in https://github.com/0x3df/LLMHound/pull/2 \
          https://github.com/0x3df/LLMHound/pull/3; do
  gh-axi pr close "${pr##*/}" && gh-axi pr reopen "${pr##*/}"
done
```

Inspect real checks and the corresponding run/logs; let each PR's existing
pipeline monitor evaluate that evidence:

```bash
for pr in https://github.com/0x3df/LLMHound/pull/2 \
          https://github.com/0x3df/LLMHound/pull/3; do
  gh-axi pr checks "${pr##*/}"
done
gh-axi run list --workflow go.yml --event pull_request
gh-axi run view <run-id> --log
```

Confirm the run belongs to the intended PR and current head/base merge, and
that Go validation actually ran. Rerunning an old run uses its original
workflow and revision; it cannot introduce a workflow that was absent then.
There is intentionally no `workflow_dispatch` or `pull_request_target` bypass.

If no run appears, check that the workflow is present in the PR merge ref,
the PR is mergeable, Actions is enabled, and any required run approval has
been granted by a maintainer. Merge conflicts block normal `pull_request`
runs. An unavailable toolchain or disabled Actions needs that specific issue
resolved; never reinterpret missing checks as success or widen token
permissions to bypass it.

References: [GitHub's pull-request event and merge-ref semantics](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#pull_request),
[`setup-go` version-file behavior](https://github.com/actions/setup-go#usage),
and [`checkout` defaults](https://github.com/actions/checkout#usage).
