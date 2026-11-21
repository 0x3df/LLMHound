# M1 CLI and Input Preparation Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement the accepted M1 CLI/configuration/target-input slice without discovery, collection, correlation, graph imports, or upload.

**Architecture:** Cobra commands load bounded strict YAML over safe defaults, replace only explicitly flagged fields, validate required deployment/vantage and policy bounds, then prepare sorted targets offline. Target parsing uses `net/netip` and syntactic FQDN validation only; it never resolves DNS. `targets` is an offline helper, not the future targets × checks `plan`.

**Tech Stack:** Installed Go 1.27.1 (module language version 1.27.0), Cobra, yaml.v3; original implementation.

## 1. Target inputs

Create `internal/targets/targets_test.go` first; run `go test ./internal/targets` to observe missing implementation. Implement `internal/targets/targets.go` with normalized IP/FQDN/CIDR input, sorted deduplication, exact hostname/IP and CIDR exclusions, line-oriented files, and useful errors. Reject URLs, ports, wildcards, invalid numeric addresses, scoped IPv6, noncanonical CIDRs, unspecified/multicast addresses, and oversized inputs. Include all addresses of a permitted CIDR (no network/broadcast omission). Bound raw expansion before exclusions, input entries, and file bytes; exclusions do not authorize an otherwise oversized expansion. Test IPv4/IPv6, malformed input, normalized names, file errors, duplicates, exclusions, and limits. Run package tests before committing.

## 2. Strict configuration

Create `internal/config/config_test.go` first; run `go test ./internal/config` to observe missing implementation. Implement `internal/config/config.go`: bounded YAML, unknown/duplicate/null/alias and multi-document rejection, defaults, explicit-field replacement overrides, validation, and file-relative input paths. Cover required scope/vantage, targets/files/exclusions, concurrency, per-host rate, connect/response timeouts, page/item/byte/redirect limits, target limit, TLS mode, User-Agent, sensitive-content opt-ins, and reserved correlation settings. Correlation configuration is stored only, never executed. Flag paths remain relative to the working directory. Test explicit false/zero/empty overrides and unchanged file values. Run package tests before committing.

## 3. Honest CLI skeleton

Create `cmd/llmhound/main_test.go` first; run `go test ./cmd/llmhound` to observe missing implementation. Implement `cmd/llmhound/main.go` and `root.go`: help/version; default optional `llmhound.yaml` and explicitly required `--config`; explicit flag replacements; offline `targets` output; `scan`, `plan`, and `upload` return actionable not-implemented errors with no fabricated artifacts. Test help/errors, file loading, flag precedence, validation, and preparation against a recording loopback listener with zero connections. No network-capable imports in these packages.

## 4. Documentation and handoff

Add `llmhound.example.yaml`, `docs/reference/configuration.md`, and the complete Apache-2.0 `LICENSE`. Update README status and distinguish working offline commands from planned milestone commands. Point AGENTS at authoritative configuration documentation and Go test/build commands. Run `gofmt`, `go test -race ./...`, `go vet ./...`, and `CGO_ENABLED=0 go build ./cmd/llmhound`, and verify an example offline invocation. Commit all implementation on `fm/llmhound-m1-cli`; firstmate owns the validation/push/PR handoff and QA merge.
