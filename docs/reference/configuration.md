# Configuration and offline target preparation

**Implemented M1 slice:** Cobra help/version, strict YAML loading, explicit flag
replacements, policy validation, and offline target preparation. No discovery,
collectors, DNS resolution/correlation, graph assembly, resume, or CE upload is
wired into the CLI. `scan`, `plan`, and `upload` exit nonzero with honest
not-implemented diagnostics and write no artifacts. `targets` is not the M2
`plan` command: it does not invent a check inventory.

## Build and use

Requires Go 1.27 or newer; developed/tested with Go 1.27.1.

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
```

An implicit `llmhound.yaml` is loaded if it exists in the working directory;
only a missing implicit default is ignored. Explicit `--config PATH` must exist
and be readable. Help/version require no configuration. Configuration and
input files are the only local files read by this slice; target service files,
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
The reserved mapping path is not read or checked for existence by this slice.

## Fields and flags

`scope` (`--scope`) and `vantage_key` (`--vantage`) are required stable keys, at
most 128 bytes without surrounding whitespace or control characters. Different
deployments/network contexts need different keys; do not use a per-run UUID.
At least one target source is required. There are no environment-variable
configuration overrides and no target-service credential fields.

| YAML field | Flag | Meaning |
|---|---|---|
| `targets` | `--targets` | IP/FQDN/CIDR inputs |
| `cidrs` | `--cidr` | Canonical IP prefixes only |
| `targets_files` | `--targets-file` | Line-oriented target inputs |
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
single-label hosts, wildcards, and invalid numeric IP spellings are rejected.
Loopback/private/documentation addresses are allowed for offline review; this is
not permission to scan them. Hostname exclusions are exact, not DNS suffixes:
excluding `example.test` does not exclude `ai.example.test`. CIDR exclusions
apply only to literal IP targets; no DNS is performed to extend them to names.
`0.0.0.0/0` or `::/0` exclusions are allowed without expansion.

Output is lexically sorted and deduplicated, one target per line. Any invalid
input fails without a partial target list. The CLI errors when exclusions leave
no targets; the internal helper returns an empty list. No scan payload or
sidecar is emitted.

### Bounds

All keys below live under `bounds`; the flag has the same name with hyphens.
Only `max_targets` currently governs executed preparation. Other bounds are
validated/stored policy for future network collectors, **not claims of currently
implemented rate limiting, pagination, redirects, or content limits**.

| Key | Default | Accepted range |
|---|---:|---|
| `max_targets` | 4096 | 1–65536 raw expanded inputs |
| `concurrency` | 16 | 1–256 |
| `per_host_rate` | 2 | finite 0.1–1000 requests/second |
| `connect_timeout` | `3s` | `1ms`–`5m` |
| `response_timeout` | `10s` | `1ms`–`5m` |
| `max_response_bytes` | 1048576 | 1–67108864 |
| `max_pages` | 100 | 1–10000 |
| `max_items` | 10000 | 1–100000 |
| `max_redirects` | 0 | 0–10 |

Raw expansion counts duplicates **before** deduplication and exclusions. A large
CIDR is rejected before iterating, even if exclusions would remove most of it.
Overlapping CIDRs consume their full expansion budgets; raise `max_targets`
within the cap or reduce inputs explicitly. Additional hard limits: 65536 total
input entries, 128 files, 1 MiB aggregate file bytes, and file lines shorter than
4096 bytes. Files must be regular files. These bounds prevent accidental
unbounded memory expansion; they are not an authorization system for future
DNS connections or redirects.

### Reserved collection and correlation policy

These values are parsed/validated, but have **no network/content effects** in M1:

- `insecure` (`--insecure`): default false; future explicit TLS verification
  bypass. Verification failure must never silently retry unverified.
- `user_agent` (`--user-agent`): default `LLMHound/dev`; nonblank printable ASCII
  up to 256 bytes. Add non-secret operator contact information if desired.
- `opt_ins.resource_content`, `.prompts`, `.configuration_content`, and
  `.workspace_content`: all default false; flags `--resource-content`,
  `--prompts`, `--configuration-content`, `--workspace-content`. Future content
  reads still require allowlisted semantics, authorization, bounds, and redaction.
- `correlation.mapping_file` (`--mapping-file`), `.ad_domain_suffixes`
  (`--ad-domain-suffix`), `.reverse_dns` (`--reverse-dns`, default false), and
  `.ce_lookup` (`--ce-lookup`, default false). Suffixes must be exact ASCII FQDNs,
  not IPs/wildcards. This slice does not read mappings, infer machine identity,
  resolve PTR records, or query CE. Correlation implementation belongs to its
  own package/milestone, per [graph-model.md](graph-model.md).

## Verification

```bash
go test -race ./...
go vet ./...
CGO_ENABLED=0 go build ./cmd/llmhound
```

Tests cover unchanged file values, explicit false/zero/empty overrides, strict
YAML types, required keys and policy ranges, normalization, bounded expansion,
file limits, deterministic exclusions, help/errors, and no DNS or loopback
connections during target preparation. Test listeners are local-only fixtures;
no production network or service credentials are needed.
