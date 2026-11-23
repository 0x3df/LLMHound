# Configuration, plan, scan, resume, and upload

**All 15 collectors and core CLI commands implemented:**
Cobra help/version, strict YAML loading, explicit flag replacements, policy validation,
offline `targets` preparation, offline `plan` (targets × allowlisted checks, no traffic),
`scan` and `resume` across all **15 supported collectors** (Jupyter, MCP, Ollama,
A2A, vLLM, Qdrant, LiteLLM, MLflow, Open WebUI, LangServe, Generic OpenAI-compatible,
Ray, Langflow, Flowise, and ChromaDB) through `internal/scanner`
(checkpoint journal, torn-tail repair on `resume`, OpenGraph base + sourceless linking
payloads, evidence sidecar, opt-in `CanExecuteOn` rules, and default-on, bounded
`.content.jsonl` content tier with high-precision secret detection), plus `upload`
for BloodHound CE validation gate, schema registration, two-step upload with read-only
existence pre-flight, and saved-query import.
Detector semantics are specified in the
[graph model](../02-graph-model.md#content-and-secrets). Live
CLI vs package coverage is recorded in [scan coverage](../internals/scan-coverage.md).

## Build and use

Requires Go 1.27 or newer (pinned in `go.mod`).

```bash
CGO_ENABLED=0 go build -o llmhound ./cmd/llmhound
./llmhound --help
./llmhound --version
./llmhound targets --config llmhound.example.yaml
# 192.0.2.2
# 192.0.2.3
# ai.example.test

# With no llmhound.yaml present, explicit required fields and inputs suffice:
./llmhound targets --scope lab --vantage scanner-a \
  --targets AI.Example.Test.,192.0.2.1 --exclude 192.0.2.0/24
# ai.example.test

./llmhound plan --scope lab --vantage scanner-a --targets 192.0.2.1
./llmhound scan --scope lab --vantage scanner-a --targets 127.0.0.1 \
  --output-dir ./out --prefix lab
```

An implicit `llmhound.yaml` is loaded if it exists in the working directory;
only a missing implicit default is ignored. Explicit `--config PATH` must exist
and be readable. Help/version require no configuration. Configuration and
input files are the only local files read for preparation; `scan` may also read
an optional `--discovery-file` fingerprint override. Target service files,
credentials, and host-local scanning are not supported.

## Precedence and strictness

Order: defaults → YAML values → **only explicitly supplied flags** → validation
→ offline preparation. An explicitly supplied false, zero, or empty value is
not ignored. List flags replace **only their own field**: `--cidr` replaces
`cidrs`, not `targets` or `targets_files`. Target sources are combined afterward.
Use `--insecure=false` to override a true file value; invalid explicit values
(e.g. `--scope=` or `--concurrency=0`) fail instead of falling back to defaults.

YAML is limited to a single mapping document of at most 64 KiB. Unknown or
duplicate keys, nulls, anchors/aliases/merges, malformed values, and implicit
scalar coercions are rejected. Write booleans as `true`/`false`, durations as
strings with units (e.g. `3s`), integers as integers, and strings as strings.
Required keys may be supplied through flags even if omitted from the file.

File-relative YAML paths (`targets_files`, `exclude_files`, `mapping_file`) are
resolved relative to the configuration directory. Paths supplied by flags are
relative to the current working directory. Empty/invalid input paths fail.
`targets` and `plan` do not open `mapping_file`; `scan` loads and validates it
when provided.

## Fields and flags

`scope` (`--scope`) and `vantage_key` (`--vantage`) are required stable keys, at
most 128 bytes without surrounding whitespace or control characters. Different
deployments/network contexts need different keys; do not use a per-run UUID.
At least one target source is required. There are no environment-variable
overrides for scan configuration (`llmhound.yaml`); only `llmhound upload` reads
`BLOODHOUND_*` connection variables. Target-service credentials are never supported.

| YAML field | Flag | Meaning |
|---|---|---|
| `targets` | `--targets` | IP/FQDN/CIDR inputs |
| `cidrs` | `--cidr` | Canonical IP prefixes only |
| `targets_files` | `--targets-file` | Line-oriented target inputs |
| `endpoints_files` | `--endpoints-file` | Pre-scanned `host:port` or `http(s)://host:port` endpoints |
| `exclude` | `--exclude` | Exact normalized IP/FQDN or CIDR exclusions |
| `exclude_files` | `--exclude-file` | Line-oriented exclusion inputs |

String-list flags accept repeated flags or comma-separated values; file flags
accept repeated flags (commas in paths are literal). Files contain one input per
line, with blank lines and `#` comments ignored. IPv4, unscoped IPv6, and ASCII
FQDNs (at least two nonempty labels) are supported. DNS names are lowercased and
one terminal dot is removed; IP representations are canonicalized, including
unmapping IPv4-mapped IPv6 literals. Internationalized names must be supplied as
ASCII punycode. IP/FQDN inputs remain distinct even if they could resolve to the
same address.

CIDRs must have no host bits set (use `192.0.2.0/24`, not `192.0.2.1/24`); every
address is included, with no network/broadcast omission. IPv4-mapped prefixes,
scoped IPv6, unspecified/multicast target addresses, URLs, ports, credentials,
single-label hosts, wildcards, and invalid numeric IP spellings are rejected;
a name whose final label is all digits or starts with `0x` (for example
`0x7f.0.0.1`) is treated as a numeric IP spelling, not an FQDN.
Loopback/private/documentation addresses are allowed for offline review; this is
not permission to scan them. Hostname exclusions are exact, not DNS suffixes:
excluding `example.test` does not exclude `ai.example.test`. CIDR exclusions
apply only to literal IP targets; no DNS is performed to extend them to names.
`0.0.0.0/0` or `::/0` exclusions are allowed without expansion.

Output is lexically sorted and deduplicated, one target per line. Any invalid
input fails without a partial target list. The CLI errors when exclusions leave
no targets; the internal helper returns an empty list. No scan payload or
sidecar is emitted.

### Scan and plan commands

- `llmhound plan`: prints prepared targets × embedded allowlisted checks for all 15
  supported surfaces (Jupyter, MCP, Ollama, A2A, vLLM, Qdrant, LiteLLM, MLflow,
  Open WebUI, LangServe, OpenAI-compatible, Ray, Langflow, Flowise, ChromaDB). No DNS,
  no target connections, no artifacts. Content-tier checks are active by default and show
  a policy skip reason when disabled via `--content=false` or `--content-disable`.
- `llmhound scan`: discovers and enumerates those surfaces, writes
  `<prefix>.journal.jsonl`, `<prefix>.json` (or `<prefix>-base.json` and
  `<prefix>-linking.json` when native mapping correlation applies),
  `<prefix>.evidence.jsonl`, and `<prefix>.content.jsonl` (written lazily only
  when bounded content records are collected). Every artifact is readable only
  by the account running the scan: mode `0600` on Unix; on Windows a protected
  DACL granting only the running user (for example the collection service
  account) and `SYSTEM`, with inherited directory ACEs removed.
  Flags: `--output-dir`, `--prefix`, `--discovery-file` (optional JSON fingerprint
  port/path overrides that inherit builtin matchers; each probe path must start
  with a single `/` and may not contain `@`, `\`, `#`, `..`, whitespace, or a
  generation/mutation prefix), `--progress-interval` (stderr progress line, default
  `30s`, `0` disables), `--result-file` (optional path for a machine-readable JSON
  lifecycle result file; see [Machine-readable result file](#machine-readable-result-file---result-file)). Only surfaces present in the active definitions are
  scanned, so `plan` and `scan` agree; `plan` is tested against the check tables
  in [the collector pages](../collectors/README.md). See
  [scan coverage](../internals/scan-coverage.md) for probe and coverage behavior.
- Interruption: Ctrl-C or SIGTERM (on Windows also console close, logoff, and
  shutdown) stops collection, closes the journal, and prints the
  `llmhound resume --journal ...` command; a second signal exits immediately.
  Each completed target is handed to the OS as it is journaled, so even a killed
  process loses at most the target in flight.
- Target errors: an unexpected error on one target is journaled as a failed
  result for that target (so `resume` retries it) and the scan continues; the
  artifacts for every other target are still written, the errors are listed on
  stderr, and the command exits non-zero. Only journal write failures and
  interruption abort a run.

### Bounds

All keys below live under `bounds`; the flag has the same name with hyphens.
`max_targets` governs executed preparation. Collectors honor configured
timeouts, concurrency, response-size, page, and item bounds where implemented;
see per-collector references.

| Key | Default | Accepted range |
|---|---:|---|
| `max_targets` | 65536 | 1–1048576 raw expanded inputs |
| `concurrency` | 64 | 1–1024 |
| `tcp_concurrency` | 512 | 1–4096 |
| `tcp_timeout` | `750ms` | `50ms`–`30s` |
| `per_host_rate` | 5 | finite 0.1–1000 requests/second |
| `connect_timeout` | `3s` | `1ms`–`5m` |
| `response_timeout` | `10s` | `1ms`–`5m` |
| `max_response_bytes` | 1048576 | 1–67108864 |
| `max_pages` | 100 | 1–10000 |
| `max_items` | 10000 | 1–100000 |
| `max_redirects` | 0 | 0–10 |

Raw expansion counts duplicates **before** deduplication and exclusions. A large
CIDR is rejected before iterating, even if exclusions would remove most of it.
Overlapping CIDRs consume their full expansion budgets; raise `max_targets`
within the cap or reduce inputs explicitly. Additional hard limits: 1,048,576
total input entries, 128 files, 16 MiB aggregate input file bytes, 32 MiB
mapping file bytes, and file lines shorter than 4096 bytes. Files must be
regular files. These bounds prevent accidental unbounded memory expansion; they
are not an authorization system for future DNS connections or redirects.

### Scan profile, graph mode & scheme (`scan.*`)

- `scan.profile` (`--profile`): `attack-path` *(default)* probes the 10
  highest-signal surfaces across 9 unique ports (`jupyter`, `ray`, `langflow`,
  `flowise`, `mcp`, `litellm`, `mlflow`, `open_webui`, `qdrant`, `ollama`);
  `rce-only` narrows to 5 direct execution/tool surfaces; `full` scans all 15
  surfaces; `--surfaces` overrides with an explicit comma-separated list.
- `scan.graph_mode` (`--graph-mode`): `attack-path` *(default)* keeps
  BloodHound CE ingestion fast by emitting `AIService` nodes (with summary
  counts and `risk_signals`), `NetworkEndpoint`s (unless `--mapped-only`),
  `ObservedAt`/`UsesBackend`/`CanExecuteOn` edges, and **only high-risk
  `MCPTool` nodes** (`capability_hint` in `shell`/`filesystem`/`secrets`/`code`),
  keeping verbose child inventories in `.evidence.jsonl`; `full` emits all child nodes.
- `scan.scheme` (`--scheme`): `auto` *(default)* tries HTTP and upgrades to
  verified HTTPS when a TLS mismatch is detected (trying HTTPS first on
  443/8443); `http` and `https` force one scheme.
- `scan.compact_json` (override with `--pretty-json`): `true` *(default)* emits
  non-indented OpenGraph JSON (~40% smaller).
- `scan.record_unmatched` (`--record-unmatched`): `false` *(default)* writes
  one lightweight `_tcp_sweep` checkpoint marker for dead hosts instead of
  10–15 failed result/evidence rows.
- `scan.mapped_only` (`--mapped-only`) omits unmapped `NetworkEndpoint` nodes
  from BloodHound payloads; `scan.mapped_only_targets` (`--mapped-only-targets`)
  restricts scanning to hosts in `mapping_file`; `scan.extra_ports`
  (`--extra-ports`) sweeps additional ports (e.g. `443,8443`).
- `scan` and `targets` also accept `--prioritize-from-bh` (`--bh-url`,
  `--bh-token-id`, `--bh-token-key`, `--bh-bearer-token`, `--bh-hops`) to query
  BloodHound CE read-only for `Tag_Tier_Zero`-adjacent nodes and scan mapped
  crown-jewel targets first. Objectids are matched case-insensitively. If a seed
  query reaches CE's ~1,000-node result cap a warning says the priority set is
  partial (ordering only; every target is still scanned).

### Collection and correlation policy

These values are parsed/validated. Scan collectors apply TLS, User-Agent, the
`content.*` content-tier policy, and mapping-file attachment:

- `insecure` (`--insecure`): default false; explicit TLS verification bypass.
  Verification failure must never silently retry unverified. Certificates are
  verified against the platform trust store: on Windows, the machine/user
  certificate store, so a target certificate issued by an internal CA verifies
  once that CA is trusted on the collection host. A certificate that fails
  verification is journaled as `TLS certificate verification failed: ...`
  (reachable, collection stopped), never as "unreachable".
- `proxy` (`--proxy`): default empty (direct connections). An explicit
  `http://`, `https://`, or `socks5://` proxy for all scan traffic (discovery
  and collection). `HTTP_PROXY`/`HTTPS_PROXY` are **ignored** for scan traffic,
  because an unannounced proxy changes the vantage the evidence claims. The
  `upload` command's connection to BloodHound CE still honors the environment
  proxy.
- `user_agent` (`--user-agent`): default `LLMHound/<build version>`; nonblank
  printable ASCII up to 256 bytes. Add non-secret operator contact information
  if desired.
- Rate and scope: `bounds.per_host_rate` is enforced by one limiter shared by
  discovery probes and every collector, so it is the rate a target actually
  sees. Collectors may contact only the prepared targets and the hosts listed in
  `--endpoints-file`; a request to any other host fails closed.
- `content.enabled` (`--content`): default `true`; `content.mode` (`--content-mode`):
  `secrets-only` *(default)* scans high-secret-yield surfaces (`jupyter`,
  `litellm`, `langflow`, `flowise`, `ray`, `open_webui`) in memory with zero
  `.content.jsonl` disk output while still setting `has_exposed_secret`;
  `metadata` skips all content-body fetches; `full` collects and writes
  bounded content across all enabled surfaces into `<prefix>.content.jsonl`
  (mode `0600`) without leaking bodies into payloads, sidecars, checkpoints, or logs.
- `content.max_item_bytes` (`--content-max-item-bytes`): default `262144`
  (256 KiB; range `1`–`16777216`).
- `content.max_items_per_resource` (`--content-max-items-per-resource`):
  default `10` (range `1`–`1000`).
- `content.max_service_bytes` (`--content-max-service-bytes`): default
  `5242880` (5 MiB; range `1`–`268435456`).
- `content.max_sample_points` (`--content-max-sample-points`): default `5`
  (range `1`–`1000`).
- `content.surfaces` (`--content-disable`): per-surface enable map in YAML
  (valid keys: `jupyter`, `mcp`, `ollama`, `a2a`, `vllm`, `qdrant`, `litellm`,
  `mlflow`, `open_webui`, `langserve`, `openai_compatible`, `ray`, `langflow`,
  `flowise`, `chromadb`); `--content-disable` accepts comma-separated or repeated
  surface names to disable content reads for those surfaces.
- `secrets.detectors`: per-detector enable map over content bodies; every
  detector is enabled unless explicitly set to `false`. Valid keys:
  `private_key` (parse-verified PEM, unencrypted), `github_token`
  (classic `ghp_/gho_/ghu_/ghs_/ghr_` tokens with a valid CRC32 checksum),
  `aws_access_key` (key id and paired secret in the same item), and
  `azure_client_secret` (paired Entra client UUID + client secret). There is no
  CLI flag and no global off switch: disabling the content tier disables
  detection with it. A match is replaced by `[secret:<type>]` in
  `.content.jsonl`, recorded by type and location in the sidecar
  (`detected_exposures`), and flagged on the graph
  (`has_exposed_secret`, `secret_types`, `secret_last_confirmed`, plus public
  identity IDs `exposed_azapp_ids`, `exposed_aws_key_ids`, `exposed_pubkey_sha256`); the value
  is never stored.
- `correlation.mapping_file` (`--mapping-file`): the asset mapping supplied by your
  external asset-inventory or normalization pipeline, which maps a target to an
  **existing BloodHound node (objectid and kind)**. Without it, every service attaches
  to a `NetworkEndpoint` for external reconciliation. LLMHound performs no
  DNS, suffix matching, or CE attribution lookups; attribution is not its job. See
  [Mapping file](#mapping-file) and
  [attachment](../02-graph-model.md#attachment-to-existing-nodes).

#### Mapping file

JSON or line-delimited, at most 1 MiB, strictly validated; conflicting entries for
one target are rejected. Targets are canonicalized like scan targets (DNS names
lower-cased, one trailing dot removed). `kind` is any native BloodHound kind
already in the graph (`Computer`, `AZVM`, ...) and defaults to `Computer`.
LLMHound's own kinds, the `LLMHound_` namespace, and malformed names are rejected.

```json
[{"target": "ai1.corp.example", "object_id": "S-1-5-21-...-1103", "kind": "Computer"},
 {"target": "10.1.2.3",         "object_id": "/SUBSCRIPTIONS/…/VIRTUALMACHINES/AI-VM1", "kind": "AZVM"}]
```

Also accepted: `{"source": "inventory-rev-2", "mappings": [...]}` (attaching `mapping_source`
provenance onto emitted attachment edges and evidence records),
`{"ai1.corp.example": "S-1-5-21-..."}` (kind defaults to `Computer`), and
lines of `target,object_id[,kind]` with `#` comments. Each entry asserts an existing
node in BloodHound; `llmhound upload` re-verifies existence against CE before sending
links because an edge to a missing objectid creates an empty stub node.

#### Path qualification (opt-in)

Top-level YAML key `path_qualification` (disabled by default):

- `enabled_rules`: list of rule IDs to enable (`jupyter-auth-disabled`,
  `ray-anonymous-jobs`, `langflow-unauthenticated-exec`,
  `flowise-unauthenticated-exec`, `openwebui-auth-disabled`,
  `azure-exposed-client-secret`, `entra-sso-code-exec`). Must be empty unless
  `assumed_reach_principals` or `vantage_principals` is non-empty.
- `assumed_reach_principals`: fallback list of `{object_id, kind}` existing
  BloodHound principals (e.g. Domain Users `S-1-5-21-...-513`) used as rule start nodes.
- `vantage_principals`: optional map of `vantage_key -> [{object_id, kind}]`
  overriding `assumed_reach_principals` per scanner network vantage.
- `cluster_fanout` (default `false`): lets `ray-anonymous-jobs` also emit edges
  to the Ray worker hosts the dashboard *declares* in `worker_hosts`. Off by
  default because that list is reported by the target itself and a spoofed
  dashboard could name any mapped host (for example a domain controller). When
  enabled, a worker must both resolve through the mapping file and be one of
  the scan's own input targets, and its edges carry `confidence: low`.
  Host execution rules always fail closed when target is unmapped
  (`NetworkEndpoint`), version is unknown/out-of-range (where checked), or
  required check evidence is missing.

### `llmhound resume` and `llmhound upload`

```bash
# Resume an interrupted scan without re-probing completed (target, surface) pairs:
./llmhound resume --journal ./out/lab.journal.jsonl --scope lab --vantage scanner-a --targets 127.0.0.1

# Validate BloodHound CE adapter contract (pinned v9.7.1) and upload payloads + queries:
./llmhound upload --url http://127.0.0.1:8080 --token-id ... --token-key ... \
  --register-schema --base-file ./out/lab-base.json --linking-file ./out/lab-linking.json --import-queries
```

`upload` flags fall back to `BLOODHOUND_URL`, `BLOODHOUND_TOKEN_ID`, `BLOODHOUND_TOKEN_KEY`,
`BLOODHOUND_BEARER_TOKEN`, `BLOODHOUND_USERNAME`, and `BLOODHOUND_PASSWORD`.
Prefer the environment variables for secrets: a `--token-key`, `--bearer-token`,
or `--password` flag (and the `--bh-*` equivalents) prints a warning, since
arguments are visible in process listings, shell history, and scheduled-task
definitions.
Upload waits for each CE ingest job by id (`?id=eq:<job>`, falling back to a
bounded `skip`/`limit` scan of the job list) and never treats a job missing
from the listing as complete. A base payload containing an edge to a node that
is not in that payload is refused before upload.
`--import-queries` replaces only LLMHound's shipped queries (names matching
`LLMHound <ID>: ...`, for example `LLMHound P1: ...`) plus exact-name matches;
analyst queries are never deleted, and if the import fails the replaced
queries are recreated.
Payloads are automatically ZIP-compressed (`--no-zip` disables) and chunked at
2,500 items (`--chunk-size`).
Pass `--enable-rules-schema` with `--register-schema` (and `--include-can-execute-on`
with `--import-queries`) only when opt-in path-qualification rules are active.
`scan`, `resume`, and `upload` all accept `--result-file <path>` to track run status in JSON.

#### Machine-readable result file (`--result-file`)

Downstream orchestrators can pass `--result-file <path>` to `llmhound scan`,
`llmhound resume`, or `llmhound upload` instead of parsing stdout/stderr. The file
uses `schema_version: "1"` and is written atomically via a restricted temp file
(`0600` on Unix; protected owner+SYSTEM DACL on Windows).

- **Lifecycle transitions:** every run writes `"status": "pending"` (with
  `exit_code`, `finished_at`, and `duration_ms` omitted) before configuration or
  upload work begins, overwriting any earlier file at that path, then transitions
  once to a terminal state:
  - `pending` -> `complete` (`exit_code: 0`)
  - `pending` -> `failed` (`exit_code: 1`, including configuration/validation
    errors, upload/gate failures, and scans where `target_error_count > 0` even
    though healthy-target artifacts were still emitted)
  - `pending` -> `interrupted` (`exit_code: 1`, when canceled via Ctrl-C,
    `SIGTERM`, or Windows shutdown/logoff)
- **Quarantine contract:** any status other than `"complete"` (`pending`,
  `failed`, `interrupted`, or a hard-killed process leaving `"pending"`) signals
  that the run must be quarantined rather than treated as healthy.
- **Safety and bounds:** `upload.url` strips userinfo, query strings, and
  fragments; secrets and credentials are never written; `scan.target_errors` and
  `upload.skipped_edges` are capped at `1000` entries with `*_truncated` flags;
  and `--result-file` refuses to collide with scan artifacts, `--journal`,
  `--base-file`, or `--linking-file`.

## Verification

```bash
go test -race ./...
go vet ./...
CGO_ENABLED=0 go build ./cmd/llmhound
```

Tests cover unchanged file values, explicit false/zero/empty overrides, strict
YAML types, required keys and policy ranges, normalization, bounded expansion,
file limits, deterministic exclusions, help/errors, offline plan (no DNS /
loopback connections), CLI scan/resume/upload against disposable loopback and mock-CE
fixtures across all 15 surfaces, and `path_qualification` validation. No production
network or service credentials are needed.
See [scan coverage](../internals/scan-coverage.md) for live vs unit coverage.
