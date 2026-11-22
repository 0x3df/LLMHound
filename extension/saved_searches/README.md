# Saved searches

Generated, not hand-edited: `go run ./tools/gensearches` renders `llmhound-p*.json` and
`llmhound-i*.json` (`P1`–`P8` and `I1`–`I7`) from `internal/savedsearch` (emitted
`LLMHound_*` kind names via `internal/graph/kinds.go`) and `path_kinds.txt`.
`go test ./internal/savedsearch` fails when the files are stale.

- **`path_kinds.txt`** is a snapshot of the traversable edge kinds on the pinned CE (built-in
  AD/Azure plus extensions, never `LLMHound_*`), taken from `GET /api/v2/extensions-edges`
  filtered client-side on `is_traversable`. Refresh it when the CE version changes.
- **P2** contains `<START_OBJECTID>`; replace it with the upper-case objectid before running
  (saved queries cannot take parameters).
- **P8** contains `<CUTOFF_ISO8601>`; replace it with a recent ISO-8601 UTC timestamp before
  running (`has_exposed_secret` is paired with `secret_last_confirmed`).
- **Import:** use `llmhound upload --import-queries` or zip the `llmhound-*.json` files and
  `POST /api/v2/saved-queries/import`. CE rejects names that already exist (HTTP 400), so
  delete the previous `LLMHound*` queries first.

Validated against CE 9.7.1 by `lab/scripts/run-d2-checks.sh` and `lab/scripts/run-m3-gate.sh`.
