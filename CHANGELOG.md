# Changelog

All notable changes to LLMHound are documented in this file.

## v1.1.0 (2026-11-23)

### Added
- **Machine-readable JSON lifecycle result file (`--result-file <path>`):** opt-in result tracking for `llmhound scan`, `llmhound resume`, and `llmhound upload` (`schema_version: "1"`). See [configuration.md](docs/guides/configuration.md#machine-readable-result-file---result-file) and [Decision 23](docs/07-decisions.md).
  - Enforces strict lifecycle transitions (`pending` -> `complete`, `pending` -> `failed`, `pending` -> `interrupted`). Any run with `status != "complete"` (including a hard-killed process left in `pending`) can be quarantined deterministically by downstream orchestrators.
  - Writes `"status": "pending"` (with `exit_code`, `finished_at`, and `duration_ms` omitted) upfront before work begins, immediately overwriting any previous file at that path.
  - Reports scan/resume runs with `target_error_count > 0` as `status: "failed"` (`exit_code: 1`, `resumable: true`) while still preserving emitted artifact paths and graph counts for healthy targets.
- **Atomic restricted file writes (`internal/securefile.WriteFileAtomic`):** writes to a restricted temporary file (`0600` on Unix; protected owner + `SYSTEM` DACL on Windows), syncs to disk, and atomically replaces the destination (`os.Rename` on Unix; `MoveFileEx` with `MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH` and bounded retry on Windows).
- **Scanner & upload lifecycle hooks and counts:**
  - `scanner.WithOnStart` updates the `pending` result file with `scan_id`, resolved `output_dir`/`prefix`, `targets_count`, and `journal_path` before target probing begins.
  - Partial `*scanner.ScanResult` metadata is preserved across post-journal errors and interruptions, and completed runs populate exact emitted `scan.counts` (`services`, `base_nodes`, `base_edges`, `linking_edges`, `evidence_records`, `exposed_secret_services`).
  - `bloodhound.UploadReport` tracks `base_uploaded`, pre-flight execution, and `linking_uploaded` accurately even when linking fails after base upload succeeds.
- **Documentation & visual:**
  - Added the standalone interactive cross-collector attack-path diagram ([`docs/assets/attack-path-sample.html`](docs/assets/attack-path-sample.html)), linked from the [docs index](docs/README.md) and [executive summary](docs/00-executive-summary.md).
  - Documented post-v1.0.0 follow-up backlog items (`F1`–`F2`) in [the roadmap](docs/06-roadmap.md).

### Security & Safety
- `upload.url` strips userinfo, query parameters, and fragments before writing to `--result-file`; credentials and secret values are never recorded.
- `scan.target_errors` and `upload.skipped_edges` are capped at 1,000 entries with `*_truncated` indicators.
- `--result-file` rejects blank/padded/control-character paths, directories, and collisions with scan artifacts, `--journal`, `--base-file`, or `--linking-file` before overwriting anything.

## v1.0.0 (2026-11-22)

- Initial release of LLMHound with 15 anonymous, read-only AI surface collectors, bounded content scanning and high-precision secret detection, opt-in path-qualification rules, crash-safe checkpoint/resume journals, and BloodHound CE `v9.7.1` two-step upload with read-only existence pre-flight and 15 saved queries.
- Post-v1 hardening for Windows service-account collection hosts: shared scan transport, explicit `--proxy`, fail-closed host allowlist, Windows owner + `SYSTEM` DACLs on artifacts, non-fatal per-target errors, and cross-platform CI/release workflows.
