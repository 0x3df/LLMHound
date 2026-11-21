#!/usr/bin/env bash
# LLMHound — D2: run the shipped saved searches against the lab with REAL emitted payloads.
#
# Pipeline under test: SharpHound attack-path fixture + AzureHound VM fixture -> real
# extension/schema.json -> `llmhound scan` against a fake Ollama (one mapped target, one
# unmapped) -> two-step upload -> extension/saved_searches/*.json run through the Cypher API
# and imported through the saved-queries API.
#
# Usage (lab up, from lab/):  bash scripts/run-d2-checks.sh
# Results: .runtime/results/d2-checks.jsonl
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"
load_lab_env
REPO_DIR="$(cd "$LAB_DIR/.." && pwd)"
RESULTS_FILE="$RESULTS_DIR/d2-checks.jsonl"; : > "$RESULTS_FILE"
WORK="$RUNTIME_DIR/d2"; mkdir -p "$WORK" "$RESULTS_DIR"
SS="$REPO_DIR/extension/saved_searches"
D=S-1-5-21-3623811015-3361044348-30300870
say() { echo "[$(date -u +%H:%M:%S)] $*"; }

wait_idle() { local i; for i in $(seq 1 90); do [ "$(call GET /api/v2/datapipe/status | jq -r '.data.status // "?"')" = idle ] && return 0; sleep 2; done; return 1; }
nodes() { cypher "MATCH (n) WHERE NOT n:MigrationData RETURN n" | jq -r '.data.nodes|length // 0' 2>/dev/null || echo 0; }
rows() { # rows CYPHER -> "status nodes edges"
    local o; o=$(cypher "$1"); printf '%s %s %s' "$(last_status)" "$(printf '%s' "$o" | jq -r '.data.nodes|length // 0' 2>/dev/null)" "$(printf '%s' "$o" | jq -r '.data.edges|length // 0' 2>/dev/null)"; }
qfile() { jq -r .query "$SS/$1"; }

cleanup() { [ -f "$WORK/p.pid" ] && kill "$(cat "$WORK/p.pid")" 2>/dev/null; return 0; }
trap cleanup EXIT

bh_login || { echo "login failed; is the lab up?" >&2; exit 1; }
say "build llmhound"; (cd "$REPO_DIR" && CGO_ENABLED=0 go build -o "$WORK/llmhound" ./cmd/llmhound) || exit 1

say "reset graph"
call POST /api/v2/clear-database '{"deleteCollectedGraphData":true}' >/dev/null
for i in $(seq 1 60); do sleep 2; [ "$(nodes)" -eq 0 ] && break; done
wait_idle; sleep 5; wait_idle

say "register real schema"
st=$(call PUT /api/v2/extensions "$(cat "$REPO_DIR/extension/schema.json")" >/dev/null; last_status)
record D2.0 "$( { [ "$st" = 200 ] || [ "$st" = 201 ]; } && echo pass || echo fail)" "$(jq -cn --arg st "$st" '{action:"PUT real extension/schema.json (no traversable rule edges)", observed:{http_status:$st}}')"

say "ingest SharpHound + AzureHound fixtures"
rm -f "$WORK/fx.zip"; (cd "$FIXTURES_DIR/ad" && zip -q -r "$WORK/fx.zip" paths -x 'paths/README.md'); (cd "$FIXTURES_DIR/azure" && zip -q "$WORK/fx.zip" ai-vm.json)
for a in 1 2 3 4; do
    upload_out "$WORK/fx.zip" application/zip fx.zip >/dev/null; wait_idle; sleep 5; wait_idle
    [ "$(cypher 'MATCH (n:Domain) RETURN n' | jq -r '.data.nodes|length' 2>/dev/null || echo 0)" -ge 1 ] 2>/dev/null && break; sleep 10
done
record D2.1 "$( [ "$(cypher 'MATCH (n:Domain) RETURN n' | jq -r '.data.nodes|length' 2>/dev/null || echo 0)" -ge 1 ] 2>/dev/null && echo pass || echo fail)" '{"action":"ingest fixtures"}'

say "scan fake Ollama with the real binary"
python3 "$FIXTURES_DIR/d2/fake_ollama.py" 11434 & echo $! > "$WORK/p.pid"; sleep 1
printf '[{"target":"127.0.0.1","object_id":"%s-1103","kind":"Computer"}]\n' "$D" > "$WORK/map.json"
printf 'scope: lab-d2\nvantage_key: scanner-a\ntargets:\n  - 127.0.0.1\n  - unmapped.localhost\nuser_agent: "LLMHound/dev (+lab@example.test)"\n' > "$WORK/cfg.yaml"
rm -rf "$WORK/out"
"$WORK/llmhound" scan --config "$WORK/cfg.yaml" --mapping-file "$WORK/map.json" --output-dir "$WORK/out" --prefix d2 >"$WORK/scan.txt" 2>&1
record D2.2 "$( [ -f "$WORK/out/d2-base.json" ] && [ -f "$WORK/out/d2-linking.json" ] && echo pass || echo fail)" "$(jq -cn --arg o "$(tail -5 "$WORK/scan.txt")" '{action:"llmhound scan, one mapped and one unmapped target", observed:$o}')"

say "two-step upload"
# A CE job can sit in "ingesting" with an idle pipeline (R-checks finding); bound each attempt
# and retry until the expected rows are queryable.
UPLOAD_WAIT=90
load_until() { # load_until FILE NAME CYPHER MIN_ROWS
    local i out
    for i in 1 2 3 4; do
        out=$(upload_out "$1" application/json "$2"); wait_idle; sleep 5
        [ "$(cypher "$3" | jq -r '(.data.nodes|length) + (.data.edges|length)' 2>/dev/null || echo 0)" -ge "$4" ] 2>/dev/null && { printf '%s' "$out" | jq -c --arg a "$i" '. + {attempts:($a|tonumber)}'; return 0; }
        say "  $2 not visible after attempt $i; retrying" >&2
    done
    printf '%s' "$out"; return 1
}
o1=$(load_until "$WORK/out/d2-base.json" d2-base.json "MATCH (s:LLMHound_AIService) RETURN s" 2); r1=$?
o2=$(load_until "$WORK/out/d2-linking.json" d2-linking.json "MATCH (s:LLMHound_AIService)-[r:LLMHound_ObservedAt]->(h) RETURN s,r,h" 3); r2=$?
record D2.3 "$( [ $r1 = 0 ] && [ $r2 = 0 ] && echo pass || echo fail)" "$(jq -cn --argjson a "$o1" --argjson b "$o2" '{action:"upload base then linking payload (retry until visible)", observed:{base:$a, linking:$b}}')"

say "run shipped queries"
chk() { # chk ID WHAT "status nodes edges" PREDICATE
    local id="$1" what="$2" got="$3" pred="$4" v=fail
    set -- $got; [ "$1" = 200 ] && eval "$pred" && v=pass
    record "$id" "$v" "$(jq -cn --arg w "$what" --arg g "$got" --arg p "$pred" '{action:$w, observed:{status_nodes_edges:$g}, expectation:$p}')"
}
chk D2.4 "P1: Domain Users -> hosts with an AI service" "$(rows "$(qfile llmhound-p1.json)")" '[ "$2" -ge 2 ] && [ "$3" -ge 1 ]'
p2=$(qfile llmhound-p2.json | sed "s/<START_OBJECTID>/$D-1701/")
chk D2.5 "P2: LOWPRIV -> hosts with an AI service" "$(rows "$p2")" '[ "$2" -ge 3 ] && [ "$3" -ge 2 ]'
chk D2.6 "P6: unattributed services" "$(rows "$(qfile llmhound-p6.json)")" '[ "$2" -eq 2 ]'
# Ollama's only surface is model_mutation, which P4 deliberately excludes: zero rows (404) is the correct answer.
chk D2.7 "P4 precision: Ollama-only graph has no code-execution surface" "$(rows "$(qfile llmhound-p4.json)" | sed 's/^404/200/')" '[ "$2" -eq 0 ]'
# Domain Admins has no outbound path to an AI host: P2 must return zero rows (HTTP 404)
iso=$(qfile llmhound-p2.json | sed "s/<START_OBJECTID>/$D-512/")
chk D2.8 "P2 negative: a start node with no path returns nothing (HTTP 404 = zero rows)" "$(rows "$iso" | sed 's/^404/200/')" '[ "$2" -eq 0 ]'
# Emitted properties as stored
props=$(cypher "MATCH (s:LLMHound_OllamaInstance) RETURN s" | jq -c '[.data.nodes[]?.properties|{auth_observed,anon_operations,exec_surface,exec_surface_basis,tls_verification,endpoint_scheme}]')
record D2.9 info "$(jq -cn --arg p "$props" '{action:"stored properties of the emitted Ollama service(s)", observed:$p}')"

say "import saved searches via the API"
# CE rejects an import whose names already exist (HTTP 400 duplicate name): remove ours first.
for id in $(call GET /api/v2/saved-queries | jq -r '.data[]|select(.name|startswith("LLMHound"))|.id'); do call DELETE "/api/v2/saved-queries/$id" >/dev/null; done
rm -f "$WORK/ss.zip"; (cd "$SS" && zip -q "$WORK/ss.zip" llmhound-p*.json)
resp=$(call_raw "$WORK/ss.zip" application/zip /api/v2/saved-queries/import); st=$(last_status)
n=$(call GET /api/v2/saved-queries | jq '[.data[]|select(.name|startswith("LLMHound"))]|length')
record D2.10 "$( [ "$st" = 201 ] && [ "$n" -ge 4 ] && echo pass || echo fail)" "$(jq -cn --arg st "$st" --arg n "$n" --arg b "$(printf '%s' "$resp" | tr -d '\n' | cut -c1-200)" '{action:"POST /api/v2/saved-queries/import of extension/saved_searches", observed:{http_status:$st, llmhound_queries_listed:$n, body:$b}}')"
say "=== done: $RESULTS_FILE ==="
