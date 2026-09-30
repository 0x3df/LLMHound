#!/usr/bin/env bash
# LLMHound M0 — repeatable live checks against the local pinned CE lab.
#
# Runs the question checks from docs/reference/ce-compatibility.md in order and
# writes one JSON line per check to .runtime/results/m0-checks.jsonl plus a
# human-readable log to .runtime/results/m0-log.txt.
#
# Requires the lab to be running (lab/scripts/lab-up.sh). Run from lab/:
#   ./scripts/run-m0-checks.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"
load_lab_env

LOG_FILE="$RESULTS_DIR/m0-log.txt"
mkdir -p "$RESULTS_DIR"
# Simple start-lock: refuse a second concurrent run (a second run would
# truncate the results file while the first is still writing evidence).
LOCK_DIR="$RUNTIME_DIR/m0-suite.lock"
if ! mkdir "$LOCK_DIR" 2>/dev/null; then
    echo "refusing: another run-m0-checks.sh appears to be running (lock: $LOCK_DIR)" >&2
    exit 1
fi
trap 'rmdir "$LOCK_DIR" 2>/dev/null' EXIT
: > "$RESULTS_DIR/m0-checks.jsonl"
exec > >(tee "$LOG_FILE") 2>&1

say()  { echo "[$(date -u +%H:%M:%S)] $*"; }

verdict_from_upload() {
    # verdict_from_upload UPLOAD_JSON — "pass" when CE rejected the payload or
    # recorded per-file errors; "deviation" when it silently accepted it.
    local u="$1"
    local v errs
    v=$(printf '%s' "$u" | jq -r '.verdict // ""')
    if [ "$v" = "rejected-http" ]; then echo pass; return; fi
    errs=$(printf '%s' "$u" | jq -r '[.tasks[]? | select((.errors|length) > 0)] | length' 2>/dev/null)
    if [ "${errs:-0}" -gt 0 ]; then echo pass; else echo deviation; fi
}

upload_out() {
    # upload_out FILE CONTENT_TYPE NAME — full job flow with captured evidence.
    # Prints JSON: {verdict, job_id, phase, http_status, body, tasks}
    local file="$1" ctype="$2" name="$3" resp st jid tasks verdict
    mkdir -p "$RUNTIME_DIR"
    resp=$(call POST /api/v2/file-upload/start)
    st=$(last_status)
    if [ "$st" != "201" ]; then
        jq -cn --arg v "rejected-http" --arg phase "start" --arg st "$st" \
            --arg b "$(printf '%s' "$resp" | tr -d '\n' | cut -c1-400)" \
            '{verdict:$v, phase:$phase, http_status:$st, body:$b}'
        return
    fi
    jid=$(printf '%s' "$resp" | jq -r '.data.id')

    resp=$(call_raw "$file" "$ctype" "/api/v2/file-upload/$jid" \
        -H "X-File-Upload-Name: $name")
    st=$(last_status)
    if [ "$st" != "202" ]; then
        jq -cn --arg v "rejected-http" --arg phase "file" --arg st "$st" \
            --arg b "$(printf '%s' "$resp" | tr -d '\n' | cut -c1-400)" \
            '{verdict:$v, phase:$phase, http_status:$st, body:$b}'
        return
    fi

    resp=$(call POST "/api/v2/file-upload/$jid/end")
    st=$(last_status)
    case "$st" in
        200|202) : ;;
        *) jq -cn --arg v "rejected-http" --arg phase "end" --arg st "$st" \
               --arg b "$(printf '%s' "$resp" | tr -d '\n' | cut -c1-400)" \
               '{verdict:$v, phase:$phase, http_status:$st, body:$b}'; return ;;
    esac

    # Ingest is asynchronous; poll to a terminal job status.
    local waited=0 jst
    while [ "$waited" -lt 300 ]; do
        jst=$(call GET /api/v2/file-upload | jq -r --arg id "$jid" '
            first(.data[] | select(.id == ($id | tonumber))).status // "gone"')
        case "$jst" in 2|3|8|gone) break ;; esac
        sleep 2
        waited=$((waited + 2))
    done
    verdict="accepted"
    tasks=$(call GET "/api/v2/file-upload/$jid/completed-tasks" \
        | jq -c '[.data[] | {file: .file_name, errors: [.errors[]? | (if type == "string" then .[0:300] else . end)]}]' 2>/dev/null)
    jq -cn --arg v "$verdict" --arg j "$jid" --arg st "${jst:-?}" \
        --argjson tasks "${tasks:-null}" \
        '{verdict:$v, job_id:$j, job_status:$st, tasks:$tasks}'
}

cypher_or_fail() {
    local q="$1"
    local out
    out=$(cypher "$q")
    if [ "$(last_status)" != "200" ]; then
        echo "CYPHER-ERROR $out"
        return
    fi
    printf '%s' "$out"
}

# CE stores node ids UPPER-CASED at ingest (observed on v9.7.1), so all
# lookups by objectid use the upper-cased form.
up_id() { printf '%s' "$1" | tr '[:lower:]' '[:upper:]'; }

node_exists() {
    # node_exists ID → prints true/false
    local id out
    id=$(up_id "$1")
    out=$(cypher_or_fail "MATCH (n {objectid: \"$id\"}) RETURN n")
    if [ "$(printf '%s' "$out" | jq -r '.data.nodes | length // 0')" -gt 0 ] 2>/dev/null; then echo true; else echo false; fi
}

kinds_of() {
    # kinds_of OBJECTID — kinds array of the node with that objectid
    local id
    id=$(up_id "$1")
    cypher_or_fail "MATCH (n {objectid: \"$id\"}) RETURN n" \
        | jq -c '[.data.nodes[] | .kinds]' 2>/dev/null
}

prop_of() {
    # prop_of OBJECTID PROP — property value(s)
    local id
    id=$(up_id "$1")
    cypher_or_fail "MATCH (n {objectid: \"$id\"}) RETURN n" \
        | jq -c "[.data.nodes[] | .properties.$2]" 2>/dev/null
}

put_extension() {
    # put_extension SCHEMA_FILE — prints HTTP status + body excerpt
    local file="$1" body
    body=$(call PUT /api/v2/extensions "$(cat "$file")")
    jq -cn --arg st "$(last_status)" \
        --arg b "$(printf '%s' "$body" | jq -c '.errors // {name: .data.name, version: .data.version, namespace: .data.namespace} // .' 2>/dev/null | cut -c1-500)" \
        '{http_status:$st, body:$b}'
}

delete_source_kinds() {
    # delete_source_kinds ID...
    call POST /api/v2/clear-database "$(jq -cn --argjson ids "[$1]" '{deleteSourceKinds:$ids}')"
    last_status
}

# ============================================================================
say "=== M0 checks against $BHE_URL ==="
# Environment facts (E-codes)
version_json=$(call GET /api/version)
record E1 pass "$(jq -cn --argjson v "$version_json" '{http_status:"200", data:$v}')"
ext_list=$(call GET /api/v2/extensions)
record E2 pass "$(jq -cn --arg st "$(last_status)" --argjson b "$(printf '%s' "$ext_list" | jq -c .)" '{pre_existing_extensions:$b}')"
img_digest=$(docker image inspect --format '{{join .RepoDigests " "}}' "docker.io/specterops/bloodhound:${BLOODHOUND_TAG:-9.7.1}" 2>/dev/null)
pg_ver=$(docker compose exec -T app-db postgres --version 2>/dev/null)
record E3 pass "$(jq -cn --arg d "$img_digest" --arg pg "$pg_ver" --arg tag "${BLOODHOUND_TAG:-9.7.1}" '{image_tag:$tag, repo_digests:$d, postgres:$pg}')"

# ============================================================================
say "=== Q1: kind namespacing and collision behavior ==="

out=$(put_extension "$FIXTURES_DIR/extension/llmhound-m0-schema.json")
verdict=$(if [[ "$(last_status)" =~ ^(200|201)$ ]]; then echo pass; else echo fail; fi)
record Q1.1 "$verdict" "$(jq -cn --argjson o "$out" '{action:"register LLMHound M0 schema (PUT /api/v2/extensions)", expected:"200/201", observed:$o}')"

out=$(put_extension "$FIXTURES_DIR/extension/toyspike-schema.json")
verdict=$(if [[ "$(last_status)" =~ ^(200|201)$ ]]; then echo pass; else echo fail; fi)
record Q1.2 "$verdict" "$(jq -cn --argjson o "$out" '{action:"register second, distinct ToySpike schema (coexistence)", expected:"200/201", observed:$o}')"

out=$(put_extension "$FIXTURES_DIR/extension/toyspike-collide-schema.json")
record Q1.3 pass "$(jq -cn --argjson o "$out" '{action:"register ToySpikeCollide schema reusing the SAME kind-name string ToySpike_MCPService", expected:"observed", observed:$o}')"

out=$(put_extension "$FIXTURES_DIR/extension/negative/m0-unprefixed-kind-schema.json")
verdict=$(if [[ "$(last_status)" =~ ^(400|409|422)$ ]]; then echo pass; else echo unexpected; fi)
record Q1.4 "$verdict" "$(jq -cn --argjson o "$out" '{action:"register schema with UNPREFIXED kind name OllamaInstance", expected:"400-range rejection per docs", observed:$o}')"

out=$(put_extension "$FIXTURES_DIR/extension/negative/m0-builtin-node-kind-schema.json")
verdict=$(if [[ "$(last_status)" =~ ^(400|409|422)$ ]]; then echo pass; else echo unexpected; fi)
record Q1.5 "$verdict" "$(jq -cn --argjson o "$out" '{action:"register schema with kind named exactly Computer (built-in overlap)", expected:"400-range rejection", observed:$o}')"

out=$(put_extension "$FIXTURES_DIR/extension/negative/m0-builtin-edge-kind-schema.json")
verdict=$(if [[ "$(last_status)" =~ ^(400|409|422)$ ]]; then echo pass; else echo unexpected; fi)
record Q1.6 "$verdict" "$(jq -cn --argjson o "$out" '{action:"register schema with edge kind named exactly MemberOf (built-in overlap)", expected:"400-range rejection", observed:$o}')"

# Re-register same schema.name with a changed version: upsert or reject?
sed 's/"version": "v0.0.1"/"version": "v0.0.2"/; s/"display_name": "LLMHound (M0 compatibility spike)"/"display_name": "LLMHound (M0 spike v2)"/' \
    "$FIXTURES_DIR/extension/llmhound-m0-schema.json" > "$RUNTIME_DIR/schema-v002.json"
out=$(put_extension "$RUNTIME_DIR/schema-v002.json")
record Q1.7 pass "$(jq -cn --argjson o "$out" '{action:"re-register same schema.name with v0.0.2", expected:"observed (docs say same schema.name overwrites)", observed:$o}')"
after=$(call GET /api/v2/extensions)
record Q1.8 pass "$(jq -cn --argjson b "$(printf '%s' "$after" | jq -c '[.data[] | {name, version}]' 2>/dev/null)" '{action:"GET /api/v2/extensions after all registrations", observed:$b}')"

edges_list=$(call GET /api/v2/extensions-edges)
record E4 pass "$(jq -cn --arg st "$(last_status)" --argjson b "$(printf '%s' "$edges_list" | jq -c . 2>/dev/null | cut -c1-600)" '{action:"GET /api/v2/extensions-edges (edge kind registry)", observed:{http_status:$st, body:$b}}')"

# ============================================================================
say "=== AD fixture: SharpHound-format synthetic Computers ==="
rm -f "$RUNTIME_DIR/ad.zip"
(cd "$FIXTURES_DIR/ad" && zip -q -r "$RUNTIME_DIR/ad.zip" ingest)
out=$(upload_out "$RUNTIME_DIR/ad.zip" application/zip "m0-lab-ad.zip")
record E5 pass "$(jq -cn --argjson o "$out" '{action:"upload synthetic AD fixture (SharpHound v6 zip)", expected:"ingest without errors", observed:$o}')"

c1=$(kinds_of "S-1-5-21-3623811015-3361044348-30300870-1103")
record E6 pass "$(jq -cn --arg k "$c1" '{action:"kinds of Computer LAB-WIN-01 after AD ingest (baseline)", observed:{kinds:$k}}')"

# ============================================================================
say "=== Q2: multi-label nodes (AIService umbrella) ==="
out=$(upload_out "$FIXTURES_DIR/payloads/base-llmhound.json" application/json "base-llmhound.json")
record Q2.1 pass "$(jq -cn --argjson o "$out" '{action:"upload base payload: nodes with kinds [LLMHound_OllamaInstance, LLMHound_AIService], metadata.source_kind=LLMHound", expected:"observed", observed:$o}')"

q=$(cypher_or_fail "MATCH (n:LLMHound_AIService) RETURN n")
record Q2.2 pass "$(jq -cn --arg n "$(printf '%s' "$q" | jq -c '[.data.nodes[] | {id: .objectId, kinds}]' 2>/dev/null)" '{action:"Cypher MATCH (n:LLMHound_AIService) — umbrella label queryable", expected:"both service nodes", observed:$n}')"

out=$(upload_out "$FIXTURES_DIR/payloads/q2b-unprefixed-umbrella.json" application/json "q2b.json")
q=$(cypher_or_fail "MATCH (n:AIService) RETURN n")
record Q2.3 pass "$(jq -cn --argjson u "$out" --arg n "$(printf '%s' "$q" | jq -c '[.data.nodes[] | {id: .objectId, kinds}]' 2>/dev/null)" '{action:"upload node with UNPREFIXED extra kind AIService; then MATCH (n:AIService)", expected:"observed", observed:{upload:$u, query:$n}}')"

# ============================================================================
say "=== Q3: property types ==="
out=$(upload_out "$FIXTURES_DIR/payloads/q3a-prop-good.json" application/json "q3a.json")
q=$(cypher_or_fail "MATCH (n {objectid: \"m0-props-good\"}) RETURN n")
props=$(printf '%s' "$q" | jq -c '.data.nodes[]?.properties | {prop_string, prop_int, prop_float, prop_bool, prop_empty_string, prop_array_strings, prop_array_numbers, prop_array_bools, PropertyName, propertyname}' 2>/dev/null)
record Q3.1 pass "$(jq -cn --argjson u "$out" --arg p "$props" '{action:"upload good-typed properties (string/int/float/bool/arrays/case-variant names) and read them back", expected:"types preserved; Name/name variants distinct", observed:{upload:$u, properties:$p}}')"

for f in q3b-prop-nested-object q3c-prop-array-of-objects q3d-prop-heterogeneous-array q3e-prop-reserved-objectid q3g-kind-tag-prefix; do
    out=$(upload_out "$FIXTURES_DIR/payloads/negative/$f.json" application/json "$f.json")
    verdict=$(verdict_from_upload "$out")
    record "Q3.$f" "$verdict" "$(jq -cn --argjson o "$out" '{action:"upload structurally-invalid payload (offline validator rejects it too)", expected:"rejection at upload or per-file ingest error", observed:$o}')"
done

out=$(upload_out "$FIXTURES_DIR/payloads/negative/q3f-id-with-colon.json" application/json "q3f.json")
q=$(cypher_or_fail "MATCH (n {objectid: \"M0:COLON:ID\"}) RETURN n")
record Q3.f pass "$(jq -cn --argjson u "$out" --arg q "$(printf '%s' "$q" | jq -c '.data.nodes | length' 2>/dev/null)" '{action:"upload node whose id contains a colon; then MATCH by that objectid", expected:"observed (docs warn colons are not fully supported)", observed:{upload:$u, query_node_count:$q}}')"

out=$(upload_out "$FIXTURES_DIR/payloads/q3h-name-uppercasing.json" application/json "q3h.json")
q=$(cypher_or_fail "MATCH (n {objectid: \"M0-UPPER\"}) RETURN n")
props=$(printf '%s' "$q" | jq -c '.data.nodes[]?.properties | {name, operatingsystem, distinguishedname}' 2>/dev/null)
record Q3.2 pass "$(jq -cn --argjson u "$out" --arg p "$props" '{action:"upload lowercase name/operatingsystem/distinguishedname values; read back", expected:"docs say these string values are uppercased at ingest", observed:{upload:$u, properties:$p}}')"

# node id case behavior: payload id m0-props-good must be stored upper-cased
q=$(cypher_or_fail "MATCH (n {objectid: \"M0-PROPS-GOOD\"}) RETURN n")
stored=$(printf '%s' "$q" | jq -c '[.data.nodes[] | {objectId, stored_objectid: .properties.objectid}]' 2>/dev/null)
record Q3.3 pass "$(jq -cn --arg s "$stored" '{action:"read back node uploaded with lowercase id m0-props-good", expected:"observed: CE stores node ids upper-cased (affects all later matching and upserts)", observed:{stored:$s}}')"

# ============================================================================
say "=== Q4: non-traversable edges vs pathfinding ==="
out=$(upload_out "$FIXTURES_DIR/payloads/q4-structured-traversal.json" application/json "q4.json")
record Q4.0 pass "$(jq -cn --argjson o "$out" '{action:"upload traversal probe graph (traversable control edges + non-traversable LLMHound edges)", observed:$o}')"

sp() {
    # sp START END [extra params] → compact {nodes, edges, edge_kinds}
    local start="$1" end="$2" extra="${3:-}"
    local out
    out=$(call GET "/api/v2/graphs/shortest-path?start_node=$start&end_node=$end$extra")
    if [ "$(last_status)" != "200" ]; then
        jq -cn --arg b "$(printf '%s' "$out" | tr -d '\n' | cut -c1-200)" --arg st "$(last_status)" '{error:$b, http:$st}'
    else
        printf '%s' "$out" | jq -c '{nodes: (.data.nodes | length), edge_kinds: [.data.edges[]? | .kind], http: 200}'
    fi
}

res=$(sp "M0-PATH-A1" "M0-PATH-A5" "&only_traversable=true")
v=$(printf '%s' "$res" | jq -r 'if (.nodes // 0) == 0 then "pass" else "deviation" end' 2>/dev/null)
record Q4.1 "$v" "$(jq -cn --arg r "$res" '{action:"shortest-path A1→A5 with only_traversable=true (chain is all non-traversable LLMHound_ObservedAt)", expected:"no path (non-traversable edges excluded)", observed:{result:$r}}')"

res=$(sp "M0-PATH-A1" "M0-PATH-A3" "&only_traversable=true")
v=$(printf '%s' "$res" | jq -r 'if (.nodes // 0) > 0 and ((.edge_kinds // []) | all(. == "LLMHound_M0TraversableControl")) then "pass" else "deviation" end' 2>/dev/null)
record Q4.2 "$v" "$(jq -cn --arg r "$res" '{action:"shortest-path A1→A3 with only_traversable=true (traversable-only route exists A1→A6→A3)", expected:"path via traversable control edges only", observed:{result:$r}}')"

res=$(sp "M0-PATH-A1" "M0-PATH-A3" "")
v=$(printf '%s' "$res" | jq -r 'if (.nodes // 0) > 0 then "pass" else "deviation" end' 2>/dev/null)
record Q4.3 "$v" "$(jq -cn --arg r "$res" '{action:"shortest-path A1→A3 with only_traversable omitted (all kinds searched)", expected:"path exists", observed:{result:$r}}')"

res=$(sp "M0-PATH-A1" "M0-PATH-A5" "&relationship_kinds=LLMHound_ObservedAt&only_traversable=true")
v=$(printf '%s' "$res" | jq -r 'if (.nodes // 0) == 0 or .error then "pass" else "deviation" end' 2>/dev/null)
record Q4.4 "$v" "$(jq -cn --arg r "$res" '{action:"shortest-path A1→A5 restricted to non-traversable LLMHound_ObservedAt with only_traversable=true", expected:"kinds excluded from search → no path", observed:{result:$r}}')"

# ============================================================================
say "=== Q5 phase A: linking edge to Computer WITH metadata.source_kind (FAQ tagging reproduction) ==="
out=$(upload_out "$FIXTURES_DIR/payloads/q5a-link-with-sourcekind.json" application/json "q5a.json")
record Q5.1 pass "$(jq -cn --argjson o "$out" '{action:"upload payload with metadata.source_kind=LLMHound whose edge references existing Computer -1103", observed:$o}')"
c=$(kinds_of "S-1-5-21-3623811015-3361044348-30300870-1103")
record Q5.2 pass "$(jq -cn --arg k "$c" '{action:"kinds of Computer -1103 AFTER hybrid upload (FAQ: source_kind may be applied to referenced AD nodes)", expected:"observed", observed:{kinds:$k}}')"

sk=$(call GET /api/v2/graphs/source-kinds)
record E7 pass "$(jq -cn --arg st "$(last_status)" --arg b "$(printf '%s' "$sk" | jq -c . | cut -c1-400)" '{action:"GET /api/v2/graphs/source_kinds", observed:{http_status:$st, body:$b}}')"

# ============================================================================
say "=== Q6: edge endpoints matched by property against existing Computers ==="
wait_for_node() {
    # wait_for_node ID [SECS] — poll until the node is queryable (ingest lag)
    local id="$1" secs="${2:-120}" waited=0
    while [ "$waited" -lt "$secs" ]; do
        [ "$(node_exists "$id")" = "true" ] && return 0
        sleep 3
        waited=$((waited + 3))
    done
    return 1
}

upload_and_check_match() {
    # upload_and_check_match FILE NAME → JSON {upload, targets}
    # Each probe payload defines its own service node (m0-match-qX), so the
    # edge query is unambiguous and never counts earlier probes' edges.
    local file="$1" name="$2" out edges svc
    svc="M0-MATCH-$(basename "$name" .json | cut -c1-3 | tr '[:lower:]' '[:upper:]')"
    out=$(upload_out "$file" application/json "$name")
    wait_for_node "$svc" 120
    edges=$(cypher_or_fail "MATCH (s {objectid: \"$svc\"})-[r:LLMHound_ObservedAt]->(c:Computer) RETURN c.objectid AS target, r.match_value AS mv, r.confidence AS conf")
    printf '%s' "$edges" | jq -cn --argjson u "$out" \
        --arg rows "$(printf '%s' "$edges" | jq -c '.data.literals // []' 2>/dev/null)" \
        '{upload:$u, targets:$rows}'
}
record Q6.1 pass "$(jq -cn --argjson o "$(upload_and_check_match "$FIXTURES_DIR/payloads/q6a-prop-match-name-lower.json" "q6a.json")" '{action:"match_by property name=lab-win-01.lab.local (lowercase) kind Computer", expected:"docs: name values uppercased at ingest; case-sensitivity behavior observed", observed:$o}')"
record Q6.2 pass "$(jq -cn --argjson o "$(upload_and_check_match "$FIXTURES_DIR/payloads/q6b-prop-match-name-upper.json" "q6b.json")" '{action:"match_by property name=LAB-WIN-01.LAB.LOCAL (exact uppercase) kind Computer", expected:"single match", observed:$o}')"
record Q6.3 pass "$(jq -cn --argjson o "$(upload_and_check_match "$FIXTURES_DIR/payloads/q6c-prop-match-zeromatch.json" "q6c.json")" '{action:"match_by property with zero candidate matches", expected:"observed (edge dropped? error?)", observed:$o}')"
record Q6.4 pass "$(jq -cn --argjson o "$(upload_and_check_match "$FIXTURES_DIR/payloads/q6d-prop-match-multi.json" "q6d.json")" '{action:"match_by property matching BOTH computers (domain property)", expected:"observed (edge to each? error?)", observed:$o}')"
record Q6.5 pass "$(jq -cn --argjson o "$(upload_and_check_match "$FIXTURES_DIR/payloads/q6e-prop-match-samaccount.json" "q6e.json")" '{action:"match_by property samaccountname=LAB-WIN-02$ kind Computer", expected:"single match", observed:$o}')"

# ============================================================================
say "=== Q7: edge endpoint matched by objectid (SID) against SharpHound Computer ==="
out=$(upload_and_check_match "$FIXTURES_DIR/payloads/q7-id-match-computer.json" "q7.json")
v=$(printf '%s' "$out" | jq -r 'if ((.targets // []) | length) == 1 then "pass" else "deviation" end')
record Q7.1 "$v" "$(jq -cn --argjson o "$out" '{action:"match_by id with SharpHound Computer SID as value", expected:"edge resolves to existing AD Computer", observed:$o}')"

# ============================================================================
say "=== Q8: upsert / rescan behavior ==="
out=$(upload_out "$FIXTURES_DIR/payloads/q8a-upsert-v1.json" application/json "q8a.json")
v1=$(prop_of "m0-upsert-1" .)
out2=$(upload_out "$FIXTURES_DIR/payloads/q8b-upsert-v2.json" application/json "q8b.json")
v2=$(prop_of "m0-upsert-1" .)
count=$(cypher_count "MATCH (n {objectid: \"M0-UPSERT-1\"}) RETURN n")
extra=$(node_exists "m0-upsert-extra")
record Q8.1 pass "$(jq -cn --argjson a "$out" --arg v1 "$v1" --argjson b "$out2" --arg v2 "$v2" --arg c "$count" --arg x "$extra" \
    '{action:"upload same node id twice (v2 changes description, drops stale_prop; v2 omits second node)", expected:"observed (update vs duplicate; stale props; absent node retained?)", observed:{v1_upload:$a, v1_props:$v1, v2_upload:$b, v2_props:$v2, node_count:$c, absent_extra_node_exists:$x}}')"

# ============================================================================
say "=== Q9: saved queries ==="
qbody=$(jq -cn '{name:"M0 Probe Query", query:"MATCH (n:LLMHound_AIService) RETURN n LIMIT 10", description:"M0 spike: umbrella-label query"}')
resp=$(call POST /api/v2/saved-queries "$qbody")
v=$(if [ "$(last_status)" = "201" ]; then echo pass; else echo deviation; fi)
record Q9.1 "$v" "$(jq -cn --arg st "$(last_status)" --arg b "$(printf '%s' "$resp" | jq -c '.data | {id, name}' 2>/dev/null)" '{action:"POST /api/v2/saved-queries {name,query,description}", expected:"201", observed:{http_status:$st, created:$b}}')"

mkdir -p "$RUNTIME_DIR/qzip" && rm -rf "$RUNTIME_DIR/qzip"/*
jq -cn '{name:"M0 Probe Query 2", query:"MATCH (v:LLMHound_CollectionVantage)-[:LLMHound_UnauthenticatedAccess]->(s) RETURN v, s LIMIT 10", description:"M0 spike: access evidence query"}' > "$RUNTIME_DIR/qzip/m0-query-2.json"
jq -cn '{name:"M0 Probe Query 3", query:"MATCH (s:LLMHound_OllamaInstance)-[:LLMHound_ProvidesModel]->(m) RETURN s, m LIMIT 10", description:"M0 spike: model inventory query"}' > "$RUNTIME_DIR/qzip/m0-query-3.json"
rm -f "$RUNTIME_DIR/m0-queries.zip" && (cd "$RUNTIME_DIR/qzip" && zip -q ../m0-queries.zip *.json)
resp=$(call_raw "$RUNTIME_DIR/m0-queries.zip" application/zip /api/v2/saved-queries/import)
v=$(if [ "$(last_status)" = "201" ]; then echo pass; else echo deviation; fi)
record Q9.2 "$v" "$(jq -cn --arg st "$(last_status)" --arg b "$(printf '%s' "$resp" | tr -d '\n' | cut -c1-200)" '{action:"POST /api/v2/saved-queries/import (zip of {name,query,description} JSONs — Query Library export format)", expected:"201", observed:{http_status:$st, body:$b}}')"

lst=$(call GET /api/v2/saved-queries)
record Q9.3 pass "$(jq -cn --arg b "$(printf '%s' "$lst" | jq -c '[.data[] | {id, name}]' 2>/dev/null | cut -c1-300)" '{action:"GET /api/v2/saved-queries to confirm imported queries", observed:$b}')"

# ============================================================================
say "=== Q10: ZIP upload handling and size ==="
python3 - <<'PYEOF'
import json, os
os.makedirs(".runtime/q10", exist_ok=True)
def probe(id, host):
    return {
        "metadata": {"source_kind": "LLMHound"},
        "graph": {"nodes": [
            {"id": id, "kinds": ["LLMHound_M0UpsertProbe"],
             "properties": {"name": id.upper(), "endpoint_host": host}}],
            "edges": [{"kind": "LLMHound_ObservedAt",
                       "start": {"match_by": "id", "value": id},
                       "end": {"match_by": "id", "value": "m0-netep-1"}}]}}
json.dump(probe("m0-zip-a", "10.0.0.1"), open(".runtime/q10/a.json", "w"))
json.dump(probe("m0-zip-b", "10.0.0.2"), open(".runtime/q10/b.json", "w"))
# size probes: many small probe nodes with distinct ids
def big(path, n, seed):
    nodes, edges = [], []
    for i in range(n):
        nid = f"m0-big-{seed}-{i}"
        nodes.append({"id": nid, "kinds": ["LLMHound_M0UpsertProbe"],
                      "properties": {"name": nid.upper(), "i": i, "seed": seed}})
    p = {"metadata": {"source_kind": "LLMHound"}, "graph": {"nodes": nodes, "edges": edges}}
    json.dump(p, open(path, "w"))
big(".runtime/q10/big-1mb.json", 4000, 1)
big(".runtime/q10/big-10mb.json", 40000, 2)
print("generated Q10 files")
PYEOF
rm -f "$RUNTIME_DIR/zip-multi.zip" && (cd "$RUNTIME_DIR/q10" && zip -q ../zip-multi.zip a.json b.json)
out=$(upload_out "$RUNTIME_DIR/zip-multi.zip" application/zip "zip-multi.zip")
ca=$(cypher_count "MATCH (n {objectid: \"M0-ZIP-A\"}) RETURN n")
cb=$(cypher_count "MATCH (n {objectid: \"M0-ZIP-B\"}) RETURN n")
v=$(if [ "$ca" = "1" ] && [ "$cb" = "1" ]; then echo pass; else echo deviation; fi)
record Q10.1 "$v" "$(jq -cn --argjson o "$out" --arg ca "$ca" --arg cb "$cb" '{action:"upload zip containing TWO payload files", expected:"both ingest", observed:{upload:$o, nodes_found:{a:$ca, b:$cb}}}')"

rm -f "$RUNTIME_DIR/zip-nested.zip"
(cd "$RUNTIME_DIR/q10" && zip -q inner.zip a.json && zip -q ../zip-nested.zip inner.zip b.json)
out=$(upload_out "$RUNTIME_DIR/zip-nested.zip" application/zip "zip-nested.zip")
v=$(verdict_from_upload "$out")
record Q10.2 "$v" "$(jq -cn --argjson o "$out" '{action:"upload zip containing a nested zip (docs: nested zips unsupported)", expected:"per-file error", observed:$o}')"

t0=$(date +%s)
out=$(upload_out "$RUNTIME_DIR/q10/big-1mb.json" application/json "big-1mb.json")
t1=$(date +%s)
cnt=$(cypher_count "MATCH (n:LLMHound_M0UpsertProbe) WHERE n.objectid STARTS WITH \"m0-big-1-\" RETURN n")
record Q10.3 pass "$(jq -cn --argjson o "$out" --arg dt "$((t1-t0))s" --arg c "$cnt" '{action:"upload ~1MB payload (4000 nodes); ingest time and node count", expected:"ingested", observed:{upload:$o, elapsed:$dt, nodes_found:$c}}')"

t0=$(date +%s)
out=$(upload_out "$RUNTIME_DIR/q10/big-10mb.json" application/json "big-10mb.json")
t1=$(date +%s)
cnt=$(cypher_count "MATCH (n:LLMHound_M0UpsertProbe) WHERE n.objectid STARTS WITH \"m0-big-2-\" RETURN n")
record Q10.4 pass "$(jq -cn --argjson o "$out" --arg dt "$((t1-t0))s" --arg c "$cnt" '{action:"upload ~10MB payload (40000 nodes); ingest time and node count", expected:"ingested", observed:{upload:$o, elapsed:$dt, nodes_found:$c}}')"

# ============================================================================
say "=== Q5 phase B: source_kind-scoped cleanup (destructive; runs last) ==="
# NOTE: the docs' GET /api/v2/graphs/source_kinds path does not exist on this
# CE build; the observed endpoint is GET /api/v2/graphs/source-kinds with
# shape {data:{kinds:[{id,name}]}}.
src=$(call GET /api/v2/graphs/source-kinds | jq -c '[.data.kinds[] | select(.name == "LLMHound")][0]')
src_id=$(printf '%s' "$src" | jq -r '.id // empty')
record Q5.3 pass "$(jq -cn --arg s "$src" '{action:"locate LLMHound in source_kinds (GET /api/v2/graphs/source-kinds)", expected:"registered by earlier metadata.source_kind payloads", observed:{source_kind:$s}}')"

if [ -n "$src_id" ]; then
    del_status=$(delete_source_kinds "$src_id")
    record Q5.4 pass "$(jq -cn --arg st "$del_status" '{action:"POST /api/v2/clear-database deleteSourceKinds=[LLMHound id]", expected:"204; deletion applied asynchronously", observed:{http_status:$st}}')"

    # deletion is asynchronous: poll until the LLMHound source record is gone
    local_wait=0
    while [ "$local_wait" -lt 180 ]; do
        still=$(call GET /api/v2/graphs/source-kinds | jq -r '[.data.kinds[] | select(.name == "LLMHound")] | length')
        [ "$still" = "0" ] && break
        sleep 5
        local_wait=$((local_wait + 5))
    done
    record Q5.4b pass "$(jq -cn --arg w "$local_wait" '{action:"poll until LLMHound source record disappears from source-kinds table", expected:"gone", observed:{waited_seconds:$w}}')"

    c1103=$(node_exists "S-1-5-21-3623811015-3361044348-30300870-1103")
    c1104=$(node_exists "S-1-5-21-3623811015-3361044348-30300870-1104")
    m0node=$(node_exists "m0-ollama-1")
    m0match=$(node_exists "m0-match-q7")
    edge1104=$(cypher_count "MATCH (s {objectid: \"M0-MATCH-Q7\"})-[r:LLMHound_ObservedAt]->(c {objectid: \"S-1-5-21-3623811015-3361044348-30300870-1104\"}) RETURN s")
    v=$(if [ "$c1104" = "true" ]; then echo pass; else echo fail; fi)
    record Q5.5 "$v" "$(jq -cn \
        --arg target "$c1103" --arg control "$c1104" --arg llm "$m0node" --arg srcless "$m0match" --arg e "$edge1104" \
        '{action:"after source deletion: Computer -1103 (WAS tagged by hybrid payload), Computer -1104 (control), LLMHound node, sourceless linking node, edge to control Computer", expected:"CRITICAL for design: tagged nodes (INCLUDING referenced AD Computer) deleted; sourceless nodes survive; no dangling edges", observed:{referenced_computer_1103:$target, control_computer_1104:$control, llmhound_node:$llm, sourceless_link_node:$srcless, edge_to_control_intact:$e}}')"

    # Workaround: re-register source with an isolated payload, then link WITHOUT source_kind
    out=$(upload_out "$FIXTURES_DIR/payloads/base-llmhound.json" application/json "base-llmhound-relink.json")
    record Q5.6 pass "$(jq -cn --argjson o "$out" '{action:"re-register LLMHound source via isolated payload (source_kind, no AD links)", observed:$o}')"

    out=$(upload_out "$FIXTURES_DIR/payloads/q5b-link-no-sourcekind.json" application/json "q5b.json")
    wait_for_node "m0-link-ollama-src" 120
    k=$(kinds_of "S-1-5-21-3623811015-3361044348-30300870-1103")
    edge=$(cypher_count "MATCH (s {objectid: \"M0-LINK-OLLAMA-SRC\"})-[r:LLMHound_ObservedAt]->(c {objectid: \"S-1-5-21-3623811015-3361044348-30300870-1103\"}) RETURN s")
    record Q5.7 pass "$(jq -cn --argjson o "$out" --arg k "$k" --arg e "$edge" \
        '{action:"workaround upload q5b: linking edge to Computer WITHOUT metadata.source_kind; then inspect Computer kinds and edge", expected:"Computer kinds clean (no LLMHound label); edge created", observed:{upload:$o, computer_1103_kinds:$k, linking_edge_count:$e}}')"

    # delete the source again: Computer must survive now (it was not tagged)
    src2=$(call GET /api/v2/graphs/source-kinds | jq -c '[.data.kinds[] | select(.name == "LLMHound")][0]')
    src2_id=$(printf '%s' "$src2" | jq -r '.id // empty')
    if [ -n "$src2_id" ]; then
        del_status=$(delete_source_kinds "$src2_id")
        local_wait=0
        while [ "$local_wait" -lt 180 ]; do
            still=$(call GET /api/v2/graphs/source-kinds | jq -r '[.data.kinds[] | select(.name == "LLMHound")] | length')
            [ "$still" = "0" ] && break
            sleep 5
            local_wait=$((local_wait + 5))
        done
        c1103b=$(node_exists "S-1-5-21-3623811015-3361044348-30300870-1103")
        srcnode=$(node_exists "m0-link-ollama-src")
        v=$(if [ "$c1103b" = "true" ]; then echo pass; else echo fail; fi)
        record Q5.8 "$v" "$(jq -cn --arg st "$del_status" --arg c "$c1103b" --arg s "$srcnode" \
            '{action:"delete source again after workaround upload", expected:"Computer -1103 SURVIVES (never tagged); sourceless linking node survives (cleanup is source-scoped)", observed:{http_status:$st, computer_1103:$c, sourceless_link_node:$s}}')"
    else
        record Q5.8 fail "$(jq -cn '{action:"delete source again after workaround upload", error:"LLMHound source missing after re-register"}')"
    fi
else
    record Q5.3 fail "$(jq -cn --arg s "$src" '{action:"locate LLMHound in source_kinds", observed:{source_kind:$s, error:"LLMHound source not found"}}')"
fi

# Final environment state after cleanup
fin=$(call GET /api/v2/extensions)
sk2=$(call GET /api/v2/graphs/source-kinds)
record E8 pass "$(jq -cn --arg e "$(printf '%s' "$fin" | jq -c '[.data[] | {name, version}]' 2>/dev/null)" --arg s "$(printf '%s' "$sk2" | jq -c . | cut -c1-300)" '{action:"final state: extensions and source_kinds after cleanup", observed:{extensions:$e, source_kinds:$s}}')"

# ============================================================================
say "=== summary ==="
jq -s -r '
    group_by(.verdict) | map({verdict: .[0].verdict, count: length})
    | map("\(.verdict)=\(.count)") | join("  ")
' "$RESULTS_DIR/m0-checks.jsonl"
echo "results: $RESULTS_DIR/m0-checks.jsonl"
echo "log:     $LOG_FILE"
