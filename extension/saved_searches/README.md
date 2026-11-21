# Saved searches

Generated, not hand-edited: `go run ./tools/gensearches` renders `llmhound-p*.json` from
`internal/savedsearch` (emitted `LLMHound_*` kind names via `internal/graph/kinds.go`) and
`path_kinds.txt`. `go test ./internal/savedsearch` fails when the files are stale.

- **`path_kinds.txt`** is a snapshot of the traversable edge kinds on the pinned CE (built-in
  AD/Azure plus extensions, never `LLMHound_*`), taken from `GET /api/v2/extensions-edges`
  filtered client-side on `is_traversable`. Refresh it when the CE version changes.
- **P2** contains `<START_OBJECTID>`; replace it with the upper-case objectid before running
  (saved queries cannot take parameters).
- **Import:** zip the `llmhound-p*.json` files and `POST /api/v2/saved-queries/import`. CE rejects
  names that already exist (HTTP 400), so delete the previous `LLMHound*` queries first.

Validated end to end by `lab/scripts/run-d2-checks.sh`.
