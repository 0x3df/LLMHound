# Roadmap

**Reading order:** 7 of 8 (see [docs index](README.md)) · The single home for milestones and
status. Order and exit criteria, not dates.

## Status at a glance

| Milestone | Scope | Status |
|---|---|---|
| **Baseline** | Docs reframed around tier-0 pathing; code aligned (no vantage node, mapping-only attachment of any native kind, access as flat properties); repo structure, legacy retirement | **Done** |
| **M0** | BloodHound CE 9.7.1 compatibility spike and reproducible [`lab/`](../lab/README.md); answers in [05](05-ce-compatibility.md) | **Done** (follow-ups R1–R9 closed) |
| **M1** | CLI, `llmhound.yaml`, targets, graph identity, emitter + sidecar, `extension/schema.json` | **Done** (shared property contract built in D1) |
| **M2a** | Discovery, checkpoint journal, `plan`/`scan`; Jupyter, MCP, Ollama collectors | **Done** |
| **M2b** | A2A, vLLM, LiteLLM, Qdrant, MLflow, Open WebUI, LangServe | In progress (A2A, vLLM, Qdrant done; LiteLLM, MLflow, Open WebUI, LangServe remaining) |
| **M2c** | Generic OpenAI-compatible endpoint, Ray, Langflow, Flowise, ChromaDB | Planned |
| **M2d** | Path-qualification rules (opt-in traversable edges) | Planned (R5 confirmed the API honors traversable rule edges) |
| **M3** | Resume, CE API client, two-step upload with existence pre-flight, saved-query import and remaining queries, adapter gate | Planned |
| **M4** | Credentialed enumeration | Future |
| **M5** | Node/edge description docs; OpenGraph community library listing (secondary goal) | Future |

## Development backlog, in order

Each item has an exit criterion. The order puts the headline queries first, because they
decide which properties must exist.

| # | Item | Exit criterion |
|---|---|---|
| **R** | **Close M0 follow-ups R1–R9** ([05](05-ce-compatibility.md#follow-up-answers-for-the-tier-0-redesign-r1r9)): tier-0 tags, typed-kind path performance, AzureHound node resolution, array overwrite, traversable rule edges, stale-property refresh, existence pre-flight call, sourceless-edge cleanup | **Done 2026-11-21.** Each answered with recorded evidence by `lab/scripts/run-r-checks.sh` |
| **D1** | **Complete the flat property contract** on the three existing collectors: `auth_advertised`, `exec_surface` (+ basis), TLS fields, `mapping_source`; every property labeled observed/declared/inferred | Contract in [02](02-graph-model.md#property-contract) matches emitted properties; golden tests cover it. **Done 2026-11-21** for endpoint, access, `exec_surface`, and TLS via `graph.ServiceFacts`. Deferred with reasons: `auth_advertised` (no collector has declared-auth evidence on an emitted node), `mapping_source` (needs a revision field in the mapping file, D8), per-field version `*_basis` labels (arrive with the collectors that report build metadata) |
| **D2** | **Headline queries on sample data**: P1, P2, P6 in [04](04-saved-queries.md) running against the lab with SharpHound/AzureHound fixtures plus emitted payloads; ship `extension/saved_searches/` | The three queries return the expected rows in the lab; query files generated from the `extensions-edges` kind list, using the shapes in [04](04-saved-queries.md). **Done 2026-11-21:** P1, P2, P6 (plus P4) return the expected rows from a real `llmhound scan` of a fake Ollama (one mapped, one unmapped target) loaded through the two-step upload, and import through the saved-queries API. P4 correctly returns nothing for Ollama (`model_mutation` is not a code-execution surface) |
| **D3** | **Content tier**: config migration `opt_ins` → `content.*` (default on, bounded), `internal/content`, restricted `.content.jsonl` | Bounds enforced and recorded as `truncated`; bodies appear only in the content file; opt-out per surface works. **Done 2026-11-21:** replaced `opt_ins` with `content.*` (default enabled, bounded, global and per-surface disable), implemented `internal/content` (`Budget`, `LazyFileWriter` mode `0600`, binary exclusion), and wired Ollama (`ollama_show`), Jupyter (`jupyter_file_content`), and MCP (`mcp_resources_read`) plus `graph.ContentSummary` properties |
| **D4** | **Secret detection**: `internal/secrets` framework and the first high-precision detectors | Every detector has a true-positive corpus and a look-alike negative corpus with **zero** false positives; raw value appears nowhere; `has_exposed_secret` is only ever `true` or unset. **Done 2026-11-21:** `internal/secrets` with `private_key` (parse-verified unencrypted PEM: PKCS#1, SEC1 EC, PKCS#8, unencrypted OpenSSH), `github_token` (classic `ghp_/gho_/ghu_/ghs_/ghr_`, base62 CRC32 checksum verified, RFC-9500/vendor-example denylist), and `aws_access_key` (key id + paired 40-char secret within 512 bytes). Wired into `content.Budget.Add` via the redactor hook, per-detector disable via `secrets.detectors`; flagged as `has_exposed_secret`/`secret_types`/`secret_last_confirmed`; value replaced by `[secret:<type>]` and recorded by type/location only (`detected_exposures`). Deferred: JWT and connection-string detectors (no checksum/parse bar met this stage; OpenAI/Anthropic keys excluded — no checksum) |
| **D5** | **M2b collectors**, one per surface, each accepted under the [capability matrix](03-collector-capabilities.md) | Per-check fixtures, honest version unknowns, TLS enforcement, authorized redirects, bounded reads. **In progress 2026-11-21:** A2A, vLLM, and Qdrant implemented and wired through `plan`/`scan` with shared `ServiceFacts` (`build_id`, `commit`, `backend_refs`, `store_refs`, inventory counts) and `internal/collectors/internal/common`; remaining: LiteLLM, MLflow, Open WebUI, LangServe |
| **D6** | **M2c long tail** | Same acceptance as D5 |
| **D7** | **M2d path-qualification**: `internal/rules`, `extension/rules`, first rules (Jupyter auth-disabled leads; Ray and Langflow follow) | Each rule meets all six criteria in [02](02-graph-model.md#path-qualification-traversable-edges), fails closed on unknown version, missing evidence, or unmapped target; R5 already verified (UI rendering still to check) |
| **D8** | **M3 upload and resume**: `internal/bloodhound`, two-step upload, existence pre-flight, `resume`, adapter validation gate | Gate re-runs `lab/scripts/run-m0-checks.sh` plus the real schema against the candidate CE; unsupported capability fails with an actionable message, local emission still works |

## Why this order

1. **R before D2 and D7.** Queries and rules depend on CE behavior that had to be verified first
   (tier-0 tags, raw-Cypher pathing, traversable edges).
2. **D1–D2 before more collectors.** Three collectors are enough to prove the headline
   queries; adding seven more first would multiply any property-contract mistake.
3. **D3–D4 before D5.** New collectors should be written against the content and secret
   frameworks, not retrofitted.
4. **D7 last among features.** Traversable edges change attack-path results; they ship only
   after the data they depend on is trustworthy and an owner is named
   ([executive summary](00-executive-summary.md#decisions-we-need-from-leadership)).

## Definition of "ready" for any milestone

- `go build ./...`, `go vet ./...`, `go test -race ./...` pass; `gofmt -l` is clean.
- The docs test (`go test ./docs`) passes: links, anchors, and the docs index are intact.
- Behavior and docs agree: the affected rows of the
  [implementation status](02-graph-model.md#implementation-status) are updated in the same change.
- No collector sends credentials, mutates a service, or reads beyond its documented bounds.
