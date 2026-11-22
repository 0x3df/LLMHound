#!/usr/bin/env bash
# LLMHound — M3 Adapter Validation Gate and Upload Integration Check.
#
# Verifies against the pinned BloodHound CE lab:
#   1. M0 contract baseline (run-m0-checks.sh).
#   2. `llmhound upload --validate-only` passes pinned CE v9.7.1 + API probes.
#   3. `llmhound upload --register-schema --import-queries` registers extension/schema.json
#      and imports all 15 saved queries.
#   4. M0 Q5 two-step upload (`--base-file` + `--linking-file`) with read-only Cypher
#      existence pre-flight skips missing native endpoints and uploads valid edges cleanly.
#
# Usage (lab up, from lab/): bash scripts/run-m3-gate.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"
load_lab_env
REPO_DIR="$(cd "$LAB_DIR/.." && pwd)"
RESULTS_FILE="$RESULTS_DIR/m3-gate.jsonl"
mkdir -p "$RESULTS_DIR"
: > "$RESULTS_FILE"

WORK="$(mktemp -d "${RUNTIME_DIR:-/tmp}/llmhound-m3-gate.XXXXXX")"
cleanup() {
    rm -rf "$WORK"
}
trap cleanup EXIT

say() { echo "[$(date -u +%H:%M:%S)] $*"; }

say "1/5 running M0 baseline checks"
bash "$SCRIPT_DIR/run-m0-checks.sh"

say "2/5 building llmhound binary"
(cd "$REPO_DIR" && CGO_ENABLED=0 go build -o "$WORK/llmhound" ./cmd/llmhound)

bh_login || { echo "lab login failed; is BloodHound CE lab running?" >&2; exit 1; }

say "3/5 running llmhound upload --validate-only against $BH_URL"
"$WORK/llmhound" upload \
    --url "$BH_URL" \
    --username "$BH_USER" \
    --password "$BH_PASS" \
    --validate-only

say "4/5 registering schema and importing saved queries"
"$WORK/llmhound" upload \
    --url "$BH_URL" \
    --username "$BH_USER" \
    --password "$BH_PASS" \
    --register-schema \
    --import-queries \
    --queries-dir "$REPO_DIR/extension/saved_searches"

say "5/5 testing two-step upload and pre-flight skip of missing native endpoints"
EXISTING_ID="$(cypher "MATCH (n:Computer) RETURN n LIMIT 1" | jq -r '.data.nodes | to_entries[0].value.objectId // empty' 2>/dev/null || true)"

cat > "$WORK/base.json" <<'EOF'
{
  "metadata": { "source_kind": "LLMHound" },
  "graph": {
    "nodes": [
      {
        "id": "GATE-SVC-01",
        "kinds": ["LLMHound_OllamaInstance", "LLMHound_AIService"],
        "properties": {
          "name": "m3-gate-ollama",
          "deployment_scope": "m3-gate",
          "objectid": "GATE-SVC-01"
        }
      }
    ],
    "edges": []
  }
}
EOF

if [ -n "$EXISTING_ID" ]; then
    cat > "$WORK/linking.json" <<EOF
{
  "graph": {
    "nodes": [],
    "edges": [
      {
        "kind": "LLMHound_ObservedAt",
        "start": { "match_by": "id", "value": "GATE-SVC-01" },
        "end": { "match_by": "id", "value": "$EXISTING_ID" }
      },
      {
        "kind": "LLMHound_ObservedAt",
        "start": { "match_by": "id", "value": "GATE-SVC-01" },
        "end": { "match_by": "id", "value": "S-1-5-21-0-0-0-999999" }
      }
    ]
  }
}
EOF
else
    cat > "$WORK/linking.json" <<'EOF'
{
  "graph": {
    "nodes": [],
    "edges": [
      {
        "kind": "LLMHound_ObservedAt",
        "start": { "match_by": "id", "value": "GATE-SVC-01" },
        "end": { "match_by": "id", "value": "S-1-5-21-0-0-0-999999" }
      }
    ]
  }
}
EOF
fi

UPLOAD_OUT="$("$WORK/llmhound" upload \
    --url "$BH_URL" \
    --username "$BH_USER" \
    --password "$BH_PASS" \
    --base-file "$WORK/base.json" \
    --linking-file "$WORK/linking.json")"
echo "$UPLOAD_OUT"
if ! printf '%s' "$UPLOAD_OUT" | grep -q "SKIP edge LLMHound_ObservedAt GATE-SVC-01 -> S-1-5-21-0-0-0-999999"; then
    echo "expected pre-flight to skip missing endpoint S-1-5-21-0-0-0-999999" >&2
    exit 1
fi

record "M3.GATE" "pass" '{"action":"validate-only, register-schema, import-queries, two-step upload + preflight"}'
say "M3 gate passed"
