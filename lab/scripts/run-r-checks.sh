#!/usr/bin/env bash
# LLMHound — redesign follow-up checks R1–R9 against the pinned CE lab.
#
# Answers the open questions in docs/05-ce-compatibility.md ("Open questions raised
# by the tier-0 redesign") with recorded evidence. Unlike M0 (a toy extension), these
# checks register the REAL extension/schema.json and use a synthetic SharpHound
# attack-path scenario (fixtures/ad/paths).
#
# Usage (from lab/, lab must be up):
#   ./scripts/run-r-checks.sh                 # reset, set up, run everything
#   ./scripts/run-r-checks.sh R4 R5           # set up, then only the named sections
#   NO_RESET=1 ./scripts/run-r-checks.sh R4   # reuse the current graph (faster iteration)
#
# Verdicts: pass (matches the design), deviation (differs from what the docs assumed),
# info (measured fact), fail (could not run). Results: .runtime/results/r-checks.jsonl
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"
load_lab_env

REPO_DIR="$(cd "$LAB_DIR/.." && pwd)"
RESULTS_FILE="$RESULTS_DIR/r-checks.jsonl"
LOG_FILE="$RESULTS_DIR/r-log.txt"
WORK="$RUNTIME_DIR/r"
mkdir -p "$RESULTS_DIR" "$WORK"
LOCK_DIR="$RUNTIME_DIR/r-suite.lock"
if ! mkdir "$LOCK_DIR" 2>/dev/null; then
    echo "refusing: another run-r-checks.sh appears to be running (lock: $LOCK_DIR)" >&2
    exit 1
fi
trap 'rmdir "$LOCK_DIR" 2>/dev/null' EXIT
[ "${NO_RESET:-0}" = "1" ] || : > "$RESULTS_FILE"
exec > >(tee -a "$LOG_FILE") 2>&1

say() { echo "[$(date -u +%H:%M:%S)] $*"; }

D=S-1-5-21-3623811015-3361044348-30300870      # scenario domain SID
SID_DU="$D-513"; SID_DA="$D-512"; SID_LOW="$D-1701"; SID_ADM="$D-1601"
SID_W1="$D-1103"; SID_W2="$D-1104"

sha() { printf '%s' "$1" | shasum -a 256 | cut -d' ' -f1 | tr 'a-f' 'A-F'; }
ID_J=$(sha "r-svc-jupyter-w1"); ID_O=$(sha "r-svc-ollama-w2"); ID_M=$(sha "r-svc-mcp-unmapped")
ID_MODEL=$(sha "r-model-llama"); ID_NE=$(sha "r-ne-unmapped")
MISSING_SID="S-1-5-21-0-0-0-9999"             # objectid that exists nowhere in the graph

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
wait_idle() {
    # wait_idle — block until the data pipe is idle (ingest + analysis finished)
    local i st
    for i in $(seq 1 90); do
        st=$(call GET /api/v2/datapipe/status | jq -r '.data.status // "?"')
        [ "$st" = "idle" ] && return 0
        sleep 2
    done
    return 1
}
count_nodes() { cypher "MATCH (n) WHERE NOT n:MigrationData RETURN n" | jq -r '.data.nodes | length // 0' 2>/dev/null || echo 0; }
qrun() {
    # qrun CYPHER — prints {status, nodes, edges, error} compactly, never aborts
    local out st
    out=$(cypher "$1" 2>/dev/null); st=$(last_status)
    jq -cn --arg st "$st" --arg b "$out" '
        ($b | try fromjson catch null) as $j
        | {status:$st,
           nodes: ($j.data.nodes // {} | length),
           edges: ($j.data.edges // [] | length),
           error: (if $st=="200" then null else ($b|gsub("\n";" ")|.[0:220]) end)}'
}
clear_graph() {
    call POST /api/v2/clear-database '{"deleteCollectedGraphData":true}' >/dev/null
    local i
    for i in $(seq 1 60); do
        sleep 2; [ "$(count_nodes)" -eq 0 ] && return 0
    done
    return 1
}
put_json_schema() { call PUT /api/v2/extensions "$(cat "$1")" >/dev/null; last_status; }
upload_json() {
    # upload_json FILE NAME — upload one JSON payload through the job flow; prints upload_out JSON
    upload_out "$1" application/json "$2"
}
payload_ok() {
    # payload_ok UPLOAD_JSON — true when accepted with no per-file errors
    printf '%s' "$1" | jq -e '(.verdict=="accepted") and ([.tasks[]?|select((.errors|length)>0)]|length==0)' >/dev/null 2>&1 && echo true || echo false
}

build_schema() {
    # The real extension schema plus the traversable CanExecuteOn kind that path-qualification
    # rules (M2d) will emit. Built from extension/schema.json so the lab never drifts from it.
    jq '.relationship_kinds += [{"name":"LLMHound_CanExecuteOn","description":"R-check only: rule-gated code execution transition.","is_traversable":true}]
        | .schema.version = "v0.1.0-rchecks"' "$REPO_DIR/extension/schema.json" > "$WORK/schema-r.json"
}

node_obj() {
    # node_obj ID KINDS_JSON PROPS_JSON
    jq -cn --arg id "$1" --argjson k "$2" --argjson p "$3" '{id:$id, kinds:$k, properties:$p}'
}
write_base_payload() {
    # write_base_payload FILE [secret_flag_json] [last_confirmed] — realistic LLMHound base payload
    local file="$1" secret="${2:-true}" conf="${3:-2026-11-20T10:00:00Z}"
    local j o m ne model edges
    j=$(node_obj "$ID_J" '["LLMHound_JupyterServer","LLMHound_AIService"]' "$(jq -cn --argjson s "$secret" --arg c "$conf" '
        {name:"Jupyter Server · lab-win-01:8888", endpoint_host:"lab-win-01.lab.local", endpoint_port:8888,
         product:"Jupyter Server", vendor:"Project Jupyter", auth_observed:"anonymous",
         anon_operations:["jupyter_contents","jupyter_sessions"], exec_surface:["code_kernel","terminal"],
         exec_surface_basis:"declared", vantage_key:"scanner-a", coverage:"complete",
         secret_types:["pem_private_key"], secret_last_confirmed:$c}
        + (if $s==null then {} else {has_exposed_secret:$s} end)')")
    o=$(node_obj "$ID_O" '["LLMHound_OllamaInstance","LLMHound_AIService"]' '{"name":"OLLAMA · lab-win-02:11434","endpoint_host":"lab-win-02.lab.local","endpoint_port":11434,"product":"Ollama","auth_observed":"anonymous","anon_operations":["ollama_tags"],"exec_surface":["model_mutation"],"exec_surface_basis":"declared","vantage_key":"scanner-a"}')
    m=$(node_obj "$ID_M" '["LLMHound_MCPServer","LLMHound_AIService"]' '{"name":"MCP · 10.9.9.9:8080","product":"demo","auth_observed":"denied","vantage_key":"scanner-a"}')
    ne=$(node_obj "$ID_NE" '["LLMHound_NetworkEndpoint"]' '{"name":"10.9.9.9","target_type":"ip"}')
    model=$(node_obj "$ID_MODEL" '["LLMHound_AIModel"]' '{"name":"LLAMA3:LATEST","digest":"sha256:aaaa"}')
    jq -n --argjson n "[$j,$o,$m,$ne,$model]" --arg io "$ID_O" --arg im "$ID_M" --arg imod "$ID_MODEL" --arg ine "$ID_NE" '
      {metadata:{source_kind:"LLMHound"}, graph:{nodes:$n, edges:[
        {kind:"LLMHound_ProvidesModel", start:{match_by:"id",value:$io}, end:{match_by:"id",value:$imod}, properties:{scan_id:"r"}},
        {kind:"LLMHound_ObservedAt", start:{match_by:"id",value:$im}, end:{match_by:"id",value:$ine}, properties:{fallback_reason:"no_mapping_entry"}}]}}' > "$file"
}
write_linking_payload() {
    # write_linking_payload FILE [extra_end_sid] — sourceless ObservedAt edges to existing native nodes
    local file="$1" extra="${2:-}"
    jq -n --arg ij "$ID_J" --arg io "$ID_O" --arg w1 "$SID_W1" --arg w2 "$SID_W2" --arg x "$extra" --arg im "$ID_M" '
      {graph:{nodes:[], edges:(
        [{kind:"LLMHound_ObservedAt", start:{match_by:"id",value:$ij}, end:{match_by:"id",value:$w1}, properties:{match_method:"mapping",confidence:"asserted"}},
         {kind:"LLMHound_ObservedAt", start:{match_by:"id",value:$io}, end:{match_by:"id",value:$w2}, properties:{match_method:"mapping",confidence:"asserted"}}]
        + (if $x=="" then [] else [{kind:"LLMHound_ObservedAt", start:{match_by:"id",value:$im}, end:{match_by:"id",value:$x}, properties:{match_method:"mapping",confidence:"asserted"}}] end))}}' > "$file"
}

# ---------------------------------------------------------------------------
# setup
# ---------------------------------------------------------------------------
setup() {
    say "=== setup: $BHE_URL ==="
    bh_login || { echo "login failed; is the lab up?" >&2; exit 1; }
    call GET /api/version | jq -c '.data' | sed 's/^/  CE: /'
    if [ "${NO_RESET:-0}" != "1" ]; then
        say "reset graph"; clear_graph || { echo "could not clear graph" >&2; exit 1; }
        wait_idle; sleep 5; wait_idle
        rm -f "$WORK/paths.zip"; (cd "$FIXTURES_DIR/ad" && zip -q -r "$WORK/paths.zip" paths -x 'paths/README.md')
        say "ingest SharpHound scenario"
        # An ingest started while the pipeline is still settling after a reset can be canceled
        # (job status 3). Retry until the AD nodes are actually queryable.
        local attempt out
        for attempt in 1 2 3 4; do
            out=$(upload_out "$WORK/paths.zip" application/zip paths.zip)
            wait_idle; sleep 5; wait_idle
            [ "$(cypher 'MATCH (n:Domain) RETURN n' | jq -r '.data.nodes|length' 2>/dev/null || echo 0)" -ge 1 ] 2>/dev/null && break
            say "  ingest attempt $attempt did not land (job_status $(printf '%s' "$out" | jq -r .job_status)); retrying"
            sleep 10
        done
        record S1 "$( [ "$(cypher 'MATCH (n:Domain) RETURN n' | jq -r '.data.nodes|length' 2>/dev/null || echo 0)" -ge 1 ] 2>/dev/null && echo pass || echo fail)" "$(jq -cn --argjson o "$out" --arg a "$attempt" '{action:"ingest fixtures/ad/paths", attempts:($a|tonumber), observed:$o}')"
    fi
    build_schema
    st=$(put_json_schema "$WORK/schema-r.json")
    record R0.1 "$( { [ "$st" = 200 ] || [ "$st" = 201 ]; } && echo pass || echo fail)" "$(jq -cn --arg st "$st" --arg b "$(call GET /api/v2/extensions | jq -c '[.data.extensions[]?|{name,version,namespace}]' | cut -c1-300)" '{action:"PUT the REAL extension/schema.json (+CanExecuteOn)", expected:"200/201", observed:{http_status:$st, extensions:$b}}')"
    say "nodes in graph: $(count_nodes)"
}

# ---------------------------------------------------------------------------
# sections are appended below
# ---------------------------------------------------------------------------

load_payloads() {
    # Base payload (source_kind) first, then the sourceless linking payload: the two-step shape.
    write_base_payload "$WORK/base.json"; write_linking_payload "$WORK/linking.json"
    out=$(upload_json "$WORK/base.json" r-base.json)
    record S2 "$( [ "$(payload_ok "$out")" = true ] && echo pass || echo fail)" "$(jq -cn --argjson o "$out" '{action:"upload base payload (source_kind LLMHound)", observed:$o}')"
    wait_idle
    out=$(upload_json "$WORK/linking.json" r-linking.json)
    record S3 "$( [ "$(payload_ok "$out")" = true ] && echo pass || echo fail)" "$(jq -cn --argjson o "$out" '{action:"upload sourceless linking payload", observed:$o}')"
    wait_idle; sleep 5
}

# ---------------------------------------------------------------------------
# R1 — how are tier-0 nodes identified, and can Cypher filter on it?
# ---------------------------------------------------------------------------
r1() {
    say "--- R1 tier-0 semantics"
    local q res
    # (a) the label, (b) the string tag, (c) the documented array form, (d) CE's own asset-group-tag
    for spec in \
      "R1.1|label Tag_Tier_Zero|MATCH (n:Tag_Tier_Zero) RETURN n" \
      "R1.2|system_tags CONTAINS|MATCH (n) WHERE n.system_tags CONTAINS 'admin_tier_0' RETURN n" \
      "R1.3|system_tags equals|MATCH (n) WHERE n.system_tags = 'admin_tier_0' RETURN n" \
      "R1.4|documented form: IN n.system_tags|MATCH (n) WHERE 'admin_tier_0' IN n.system_tags RETURN n"; do
        IFS='|' read -r id what q <<<"$spec"
        res=$(qrun "$q")
        record "$id" info "$(jq -cn --arg w "$what" --arg q "$q" --argjson r "$res" '{action:$w, query:$q, observed:$r}')"
    done
    local t0 tags
    tags=$(call GET /api/v2/asset-group-tags | jq -c '[.data.tags[]|{id,name,type}]')
    t0=$(call GET /api/v2/asset-group-tags/1/members | jq -c '[.data.members[]? | {name:(.name // .object_id), primary_kind}]' 2>/dev/null | cut -c1-600)
    record R1.5 info "$(jq -cn --arg tags "$tags" --arg m "$t0" --arg st "$(last_status)" '{action:"CE asset-group tags and Tier Zero members endpoint", observed:{tags:$tags, tier_zero_members_http:$st, members:$m}}')"
    local ty
    ty=$(cypher "MATCH (n:Tag_Tier_Zero {name:\"DOMAIN ADMINS@LAB.LOCAL\"}) RETURN n" | jq -c '[.data.nodes|to_entries[]|.value.properties|{system_tags, system_tags_type:(.system_tags|type), kinds_has_tag:true}]' 2>/dev/null)
    record R1.6 info "$(jq -cn --arg t "$ty" '{action:"property type of system_tags and isTierZero on a tier-0 node", observed:$t}')"
}

main() {
    setup
    [ "${NO_RESET:-0}" = "1" ] || load_payloads
    local sections=("$@")
    [ "${#sections[@]}" -gt 0 ] || sections=(R1 R3 R4 R6 R5 R9 R7 R2 R8)
    for s in "${sections[@]}"; do
        case "$s" in
            R1) r1 ;; R2) r2 ;; R2b) r2b ;; R3) r3 ;; R4) r4 ;; R5) r5 ;; R6) r6 ;; R7) r7 ;; R8) r8 ;; R9) r9 ;;
            *) echo "unknown section $s" >&2 ;;
        esac
    done
    say "=== done; results: $RESULTS_FILE ==="
}

# ---------------------------------------------------------------------------
# R3 — can a linking edge resolve AzureHound-ingested nodes by objectid?
# ---------------------------------------------------------------------------
ARM_UPPER="/SUBSCRIPTIONS/AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE/RESOURCEGROUPS/RG1/PROVIDERS/MICROSOFT.COMPUTE/VIRTUALMACHINES/AI-VM1"
ARM_LOWER=$(printf '%s' "$ARM_UPPER" | tr 'A-Z' 'a-z')
VM_GUID="ABCDEF01-2345-6789-ABCD-EF0123456789"
r3() {
    say "--- R3 AzureHound node resolution"
    local out
    out=$(upload_json "$FIXTURES_DIR/azure/ai-vm.json" ai-vm.json); wait_idle; sleep 5
    record R3.1 "$( [ "$(payload_ok "$out")" = true ] && echo pass || echo fail)" "$(jq -cn --argjson o "$out" '{action:"ingest AzureHound-format AZVM fixture", observed:$o}')"
    local vm
    vm=$(cypher "MATCH (n:AZVM) RETURN n" | jq -c '[.data.nodes|to_entries[]|.value|{kinds, objectid:.properties.objectid, name:.properties.name}]')
    record R3.2 info "$(jq -cn --arg v "$vm" --arg guid "$VM_GUID" '{action:"objectid CE assigns an AZVM", observed:{azvm:$v, vm_guid_in_payload:$guid}}')"
    # Three attachment attempts from the unmapped MCP service, each with its own edge kind so a
    # lower-cased id that resolves to the same node as the exact one is still distinguishable.
    local f="$WORK/r3-link.json" k
    jq -n --arg im "$ID_M" --arg a "$ARM_UPPER" --arg b "$ARM_LOWER" --arg c "$VM_GUID" '
      {graph:{nodes:[], edges:[
       {kind:"LLMHound_ObservedAt", start:{match_by:"id",value:$im}, end:{match_by:"id",value:$a}, properties:{case:"exact"}},
       {kind:"LLMHound_RunsOn",     start:{match_by:"id",value:$im}, end:{match_by:"id",value:$b}, properties:{case:"lower"}},
       {kind:"LLMHound_Contains",   start:{match_by:"id",value:$im}, end:{match_by:"id",value:$c}, properties:{case:"guid"}}]}}' > "$f"
    out=$(upload_json "$f" r3-link.json); wait_idle; sleep 5
    local res=""
    for k in ObservedAt RunsOn Contains; do
        res+=$(cypher "MATCH (s {objectid:\"$ID_M\"})-[r:LLMHound_$k]->(t) RETURN s, r, t" \
            | jq -c --arg k "$k" '{edge:$k, ends:[.data.nodes|to_entries[]|.value|select(.kinds|index("LLMHound_MCPServer")|not)|{id:.properties.objectid, kinds}]}' 2>/dev/null)$'\n'
    done
    local exact lower guid
    exact=$(printf '%s' "$res" | jq -c 'select(.edge=="ObservedAt")|.ends[]|select(.id|startswith("/SUBSCRIPTIONS"))|.kinds' | head -1)
    lower=$(printf '%s' "$res" | jq -c 'select(.edge=="RunsOn")|.ends' )
    guid=$(printf '%s' "$res" | jq -c 'select(.edge=="Contains")|.ends')
    record R3.3 "$( printf '%s' "$exact" | grep -q AZVM && echo pass || echo deviation)" "$(jq -cn --arg e "$exact" '{action:"match_by id with the exact upper-cased ARM id", expected:"edge to the existing AZVM node", observed:{end_kinds:$e}}')"
    record R3.4 info "$(jq -cn --arg l "$lower" --arg g "$guid" '{action:"lower-cased ARM id and the VM GUID as match_by id (own edge kinds)", note:"an end node with kinds [] is an empty stub CE created instead of resolving; no end node means the edge was dropped or resolved to the exact node", observed:{lowercase_ends:$l, guid_ends:$g}}')"
}

# ---------------------------------------------------------------------------
# generic helpers for the remaining sections
# ---------------------------------------------------------------------------
jprops() { # jprops OBJECTID — properties object of the node
    cypher "MATCH (n {objectid:\"$(up_id "$1")\"}) RETURN n" | jq -c '[.data.nodes[]?.properties][0] // {}'
}
sp() { # sp START END [extra query string] — shortest-path API; prints {status, nodes, edges:[kinds]}
    local out st
    out=$(call GET "/api/v2/graphs/shortest-path?start_node=$(up_id "$1")&end_node=$(up_id "$2")${3:-}"); st=$(last_status)
    jq -cn --arg st "$st" --arg b "$out" '($b|try fromjson catch null) as $j
        | {status:$st, nodes:($j.data.nodes//{}|length), edge_kinds:[$j.data.edges[]?.label], error:(if $st=="200" then null else ($b|gsub("\n";" ")|.[0:200]) end)}'
}
now_ms() { python3 -c 'import time;print(int(time.time()*1000))'; }

# ---------------------------------------------------------------------------
# R4 — array and edge-property overwrite on re-upload
# ---------------------------------------------------------------------------
r4() {
    say "--- R4 array / edge property overwrite"
    local before out after eb ea
    before=$(jprops "$ID_J" | jq -c '{anon_operations, exec_surface}')
    # shrink both arrays and change the edge property
    jq --arg ij "$ID_J" '(.graph.nodes[]|select(.id==$ij)|.properties) |= (.anon_operations=["jupyter_contents"] | .exec_surface=["code_kernel"])
        | (.graph.edges[]|select(.kind=="LLMHound_ProvidesModel")|.properties.scan_id)="r4-second"' "$WORK/base.json" > "$WORK/base-r4.json"
    out=$(upload_json "$WORK/base-r4.json" r4-base.json); wait_idle; sleep 3
    after=$(jprops "$ID_J" | jq -c '{anon_operations, exec_surface}')
    record R4.1 "$( [ "$(printf '%s' "$after" | jq -c .anon_operations)" = '["jupyter_contents"]' ] && echo pass || echo deviation)" "$(jq -cn --arg b "$before" --arg a "$after" --argjson u "$out" '{action:"re-upload node with SHORTER array properties", expected:"array replaced (no stale elements)", observed:{before:$b, after:$a, upload_ok:($u.verdict)}}')"
    ea=$(cypher "MATCH ()-[r:LLMHound_ProvidesModel]->() RETURN r" | jq -c '[.data.edges[]?|.properties]')
    record R4.2 "$( printf '%s' "$ea" | grep -q 'r4-second' && echo pass || echo deviation)" "$(jq -cn --arg e "$ea" '{action:"re-upload same edge (same start/end/kind) with a changed property", expected:"property updated, still one edge", observed:$e}')"
    # now grow the array again and add a new key; confirm the order/duplicates behavior
    jq --arg ij "$ID_J" '(.graph.nodes[]|select(.id==$ij)|.properties.anon_operations)=["jupyter_sessions","jupyter_contents","jupyter_contents"]' "$WORK/base.json" > "$WORK/base-r4b.json"
    upload_json "$WORK/base-r4b.json" r4b.json >/dev/null; wait_idle; sleep 3
    record R4.3 info "$(jq -cn --arg a "$(jprops "$ID_J" | jq -c .anon_operations)" '{action:"re-upload array with duplicates and different order", observed:{stored:$a}, note:"stored verbatim means CE does not dedupe or sort; collectors must emit sorted unique arrays"}')"
    # restore baseline for later sections
    upload_json "$WORK/base.json" base.json >/dev/null; wait_idle; sleep 3
}

# ---------------------------------------------------------------------------
# R6 — stale boolean persistence and the freshness pattern
# ---------------------------------------------------------------------------
r6() {
    say "--- R6 stale property persistence"
    local out p
    # latest scan: secret no longer found -> has_exposed_secret omitted, newer confirmation not emitted either
    write_base_payload "$WORK/base-r6a.json" null "2026-11-21T10:00:00Z"
    jq --arg ij "$ID_J" '(.graph.nodes[]|select(.id==$ij)|.properties) |= del(.secret_types)' "$WORK/base-r6a.json" > "$WORK/base-r6a2.json"
    upload_json "$WORK/base-r6a2.json" r6a.json >/dev/null; wait_idle; sleep 3
    p=$(jprops "$ID_J" | jq -c '{has_exposed_secret, secret_types, secret_last_confirmed}')
    record R6.1 "$( [ "$(printf '%s' "$p" | jq -r .has_exposed_secret)" = true ] && echo info || echo deviation)" "$(jq -cn --arg p "$p" '{action:"re-upload service WITHOUT has_exposed_secret / secret_types (secret remediated)", observed:$p, note:"true means omission never clears a property: a stale true survives; consumers must gate on secret_last_confirmed"}')"
    # refresh pattern A: emit explicit false
    write_base_payload "$WORK/base-r6b.json" false "2026-11-21T11:00:00Z"
    upload_json "$WORK/base-r6b.json" r6b.json >/dev/null; wait_idle; sleep 3
    p=$(jprops "$ID_J" | jq -c '{has_exposed_secret, secret_last_confirmed}')
    record R6.2 "$( [ "$(printf '%s' "$p" | jq -r .has_exposed_secret)" = false ] && echo info || echo deviation)" "$(jq -cn --arg p "$p" '{action:"refresh pattern: re-upload with explicit has_exposed_secret=false", observed:$p, note:"explicit false overwrites; but false asserts absence, which the precision rule forbids unless the scan completed the detector surface"}')"
    # refresh pattern B: freshness timestamp, query filters on it
    write_base_payload "$WORK/base-r6c.json" true "2026-11-21T12:00:00Z"
    upload_json "$WORK/base-r6c.json" r6c.json >/dev/null; wait_idle; sleep 3
    local res
    res=$(qrun "MATCH (s:LLMHound_AIService) WHERE s.has_exposed_secret = true AND s.secret_last_confirmed >= '2026-11-21T00:00:00Z' RETURN s")
    record R6.3 info "$(jq -cn --argjson r "$res" '{action:"query pattern: has_exposed_secret=true AND secret_last_confirmed >= cutoff (ISO-8601 string comparison)", observed:$r}')"
    # also: can a property be removed at all? try explicit null
    jq --arg ij "$ID_J" '(.graph.nodes[]|select(.id==$ij)|.properties.has_exposed_secret)=null' "$WORK/base.json" > "$WORK/base-r6d.json"
    out=$(upload_json "$WORK/base-r6d.json" r6d.json); wait_idle; sleep 3
    p=$(jprops "$ID_J" | jq -c '{has_exposed_secret, has_key:(has("has_exposed_secret"))}')
    record R6.4 info "$(jq -cn --arg p "$p" --argjson u "$out" '{action:"re-upload with has_exposed_secret=null", observed:{props:$p, upload:$u.verdict, job_status:$u.job_status}}')"
    upload_json "$WORK/base.json" base.json >/dev/null; wait_idle; sleep 3
}

# ---------------------------------------------------------------------------
# R5 / R9 — traversable edges and relationship_kinds in pathfinding
# ---------------------------------------------------------------------------
r5() {
    say "--- R5 traversable edge honored by pathfinding"
    local f="$WORK/exec.json" pre post kinds ee
    pre=$(sp "$ID_J" "$SID_DA" "&only_traversable=true")
    jq -n --arg ij "$ID_J" --arg w1 "$SID_W1" '{graph:{nodes:[],edges:[{kind:"LLMHound_CanExecuteOn",start:{match_by:"id",value:$ij},end:{match_by:"id",value:$w1},properties:{rule:"r-check"}}]}}' > "$f"
    upload_json "$f" exec.json >/dev/null; wait_idle; sleep 5
    post=$(sp "$ID_J" "$SID_DA" "&only_traversable=true")
    local all
    all=$(sp "$ID_J" "$SID_DA" "")
    record R5.1 "$( [ "$(printf '%s' "$pre" | jq -r .status)" != 200 ] && [ "$(printf '%s' "$post" | jq -r .nodes)" -gt 0 ] && echo pass || echo deviation)" "$(jq -cn --argjson a "$pre" --argjson b "$post" --argjson c "$all" '{action:"service -> Domain Admins, only_traversable=true, before vs after adding traversable LLMHound_CanExecuteOn (service->Computer, sourceless)", expected:"no path before; path through CanExecuteOn after", observed:{before:$a, after:$b, without_filter_after:$c}}')"
    # non-traversable ObservedAt must NOT be followed when only_traversable=true
    ee=$(call GET "/api/v2/extensions-edges?is_traversable=true" | jq -c '[.data|(.. |objects|select(has("name"))|.name)]' 2>/dev/null | cut -c1-400)
    record R5.2 info "$(jq -cn --arg e "$ee" '{action:"extensions-edges?is_traversable=true lists the extension traversable kinds", observed:$e}')"
    # reverse direction: does path from the Computer to the service exist via ObservedAt? (edge direction matters)
    record R5.3 info "$(jq -cn --argjson r "$(sp "$SID_W1" "$ID_J" "")" '{action:"Computer -> service, no filter (ObservedAt points service->Computer; CanExecuteOn service->Computer)", observed:$r}')"
}
r9() {
    say "--- R9 relationship_kinds filter"
    local a b c d
    a=$(sp "$SID_LOW" "$SID_DA" "")
    b=$(sp "$SID_LOW" "$SID_DA" "&relationship_kinds=in:MemberOf,GenericAll,HasSession")
    c=$(sp "$SID_LOW" "$SID_DA" "&relationship_kinds=nin:GenericAll")
    d=$(sp "$ID_J" "$SID_DA" "&relationship_kinds=in:LLMHound_CanExecuteOn,HasSession,MemberOf")
    record R9.1 info "$(jq -cn --argjson a "$a" --argjson b "$b" --argjson c "$c" '{action:"LOWPRIV -> Domain Admins with relationship_kinds in:/nin: on native kinds", observed:{no_filter:$a, in_native:$b, nin_GenericAll:$c}}')"
    record R9.2 info "$(jq -cn --argjson d "$d" '{action:"relationship_kinds in: with an extension kind (LLMHound_CanExecuteOn) mixed with native kinds, on live data", observed:$d}')"
    local e
    e=$(sp "$ID_J" "$SID_DA" "&relationship_kinds=in:LLMHound_NoSuchKind")
    record R9.3 info "$(jq -cn --argjson e "$e" '{action:"relationship_kinds with an unknown kind", observed:$e}')"
}

# ---------------------------------------------------------------------------
# R7 — existence pre-flight
# ---------------------------------------------------------------------------
r7() {
    say "--- R7 existence pre-flight"
    local ids q res t0 t1 miss
    ids="\"$(up_id "$SID_W1")\",\"$(up_id "$SID_W2")\",\"$MISSING_SID\",\"$(up_id "$ARM_UPPER")\",\"$VM_GUID\""
    q="MATCH (n) WHERE n.objectid IN [$ids] RETURN n"
    res=$(cypher "$q" | jq -c '[.data.nodes[]?|{id:.properties.objectid, kinds}]')
    record R7.1 info "$(jq -cn --arg r "$res" '{action:"one Cypher IN-list returns what exists, with kinds", observed:$r, note:"an id absent from the result does not exist; a result with kinds [] (e.g. the VM GUID) is a stub and must be treated as NOT existing"}')"
    # a sourceless edge to an id that exists nowhere creates a stub
    write_linking_payload "$WORK/link-missing.json" "$MISSING_SID"
    upload_json "$WORK/link-missing.json" link-missing.json >/dev/null; wait_idle; sleep 5
    miss=$(cypher "MATCH (n {objectid:\"$MISSING_SID\"}) RETURN n" | jq -c '[.data.nodes[]?|{kinds, props:(.properties|keys)}]')
    record R7.2 info "$(jq -cn --arg m "$miss" '{action:"sourceless edge to a nonexistent objectid", observed:$m, note:"confirms the stub is kindless: the pre-flight predicate is has-a-native-kind"}')"
    # no-stub predicate query for already-polluted graphs
    res=$(qrun "MATCH (n) WHERE size(labels(n)) = 0 RETURN n")
    record R7.3 info "$(jq -cn --argjson r "$res" '{action:"find existing stubs with size(labels(n)) = 0", observed:$r}')"
    res=$(qrun "MATCH (n) WHERE NOT n:Base AND NOT n:AZBase AND NOT n:LLMHound AND NOT n:MigrationData RETURN n")
    record R7.4 info "$(jq -cn --argjson r "$res" '{action:"find stubs by kind absence", observed:$r}')"
    # scale: 500-id IN list
    local big
    big=$(python3 - <<PY
print(",".join('"S-1-5-21-0-0-0-%d"'%i for i in range(1000,1500)))
PY
)
    t0=$(now_ms); res=$(qrun "MATCH (n) WHERE n.objectid IN [$big,\"$(up_id "$SID_W1")\"] RETURN n"); t1=$(now_ms)
    record R7.5 info "$(jq -cn --argjson r "$res" --arg ms "$((t1-t0))" '{action:"501-id IN-list", observed:$r, elapsed_ms:($ms|tonumber)}')"
}

# ---------------------------------------------------------------------------
# R8 — cleanup semantics (destructive; keep last)
# ---------------------------------------------------------------------------
r8() {
    say "--- R8 cleanup semantics (destructive)"
    local src n0 n1 st res rel i stubs0 stubs1 aisvc
    count_native() { cypher "MATCH (n) WHERE n:Computer OR n:User OR n:Group OR n:Domain OR n:AZVM RETURN n" | jq -r '.data.nodes|length // 0'; }
    count_edges() { local o; o=$(cypher "MATCH ()-[r:$1]->() RETURN r"); [ "$(last_status)" = 404 ] && { echo 0; return; }; printf '%s' "$o" | jq -r '.data.edges|length // 0'; }
    wait_edges_zero() { local i; for i in $(seq 1 45); do [ "$(count_edges "$1")" = 0 ] && return 0; sleep 4; done; return 1; }
    ensure_loaded() { # reload both payloads until the service nodes exist
        local k
        for k in 1 2 3; do wait_idle; sleep 5; load_payloads
            [ "$(cypher 'MATCH (n:LLMHound_AIService) RETURN n' | jq -r '.data.nodes|length // 0')" -ge 3 ] 2>/dev/null && return 0
            say "  payload did not land (attempt $k); retrying"; done; return 1; }

    ensure_loaded || say "WARN: could not load payloads"
    n0=$(count_native); rel=$(count_edges LLMHound_ObservedAt)
    call POST /api/v2/clear-database '{"deleteRelationships":["LLMHound_ObservedAt"]}' >/dev/null; st=$(last_status)
    wait_edges_zero LLMHound_ObservedAt; local ok=$?
    wait_idle; n1=$(count_native)
    aisvc=$(cypher 'MATCH (n:LLMHound_AIService) RETURN n' | jq -r '.data.nodes|length // 0')
    record R8.1 "$( [ "$ok" = 0 ] && [ "$n0" = "$n1" ] && echo pass || echo deviation)" "$(jq -cn --arg st "$st" --arg b "$rel" --arg a "$(count_edges LLMHound_ObservedAt)" --arg n0 "$n0" --arg n1 "$n1" --arg s "$aisvc" '{action:"clear-database deleteRelationships:[LLMHound_ObservedAt] (all ObservedAt edges: both sourced and sourceless)", expected:"ObservedAt edges gone (async), native and LLMHound nodes untouched", observed:{http_status:$st, edges_before:$b, edges_after_wait:$a, native_before:$n0, native_after:$n1, llmhound_services_left:$s}}')"

    ensure_loaded || say "WARN: could not load payloads"
    src=$(call GET /api/v2/graphs/source-kinds | jq -r '[.data.kinds[]|select(.name=="LLMHound")][0].id')
    n0=$(count_native); stubs0=$(cypher "MATCH (n) WHERE size(labels(n)) = 0 RETURN n" | jq -r '.data.nodes|length // 0')
    call POST /api/v2/clear-database "$(jq -cn --argjson i "${src:-0}" '{deleteSourceKinds:[$i]}')" >/dev/null; st=$(last_status)
    for i in $(seq 1 45); do sleep 4; [ "$(cypher 'MATCH (n:LLMHound_AIService) RETURN n' | jq -r '.data.nodes|length // 0')" = 0 ] && break; done
    wait_idle; sleep 3
    n1=$(count_native); stubs1=$(cypher "MATCH (n) WHERE size(labels(n)) = 0 RETURN n" | jq -r '.data.nodes|length // 0')
    rel=$(count_edges LLMHound_ObservedAt)
    record R8.2 "$( [ "$n0" = "$n1" ] && [ "$(cypher 'MATCH (n:LLMHound_AIService) RETURN n' | jq -r '.data.nodes|length // 0')" = 0 ] && echo pass || echo deviation)" "$(jq -cn --arg st "$st" --arg src "$src" --arg n0 "$n0" --arg n1 "$n1" --arg s0 "$stubs0" --arg s1 "$stubs1" --arg rel "$rel" '{action:"clear-database deleteSourceKinds:[LLMHound id] after the two-step load", expected:"LLMHound nodes gone, native nodes intact, attachment edges gone", observed:{http_status:$st, source_kind_id:$src, native_before:$n0, native_after:$n1, kindless_stubs_before:$s0, kindless_stubs_after:$s1, observedat_edges_left:$rel}}')"

    ensure_loaded || say "WARN: could not load payloads"
    n0=$(count_native); stubs0=$(cypher "MATCH (n) WHERE size(labels(n)) = 0 RETURN n" | jq -r '.data.nodes|length // 0')
    call POST /api/v2/clear-database '{"deleteSourceKinds":[0]}' >/dev/null; st=$(last_status); wait_idle; sleep 10; wait_idle
    n1=$(count_native); stubs1=$(cypher "MATCH (n) WHERE size(labels(n)) = 0 RETURN n" | jq -r '.data.nodes|length // 0')
    aisvc=$(cypher 'MATCH (n:LLMHound_AIService) RETURN n' | jq -r '.data.nodes|length // 0')
    record R8.3 info "$(jq -cn --arg st "$st" --arg n0 "$n0" --arg n1 "$n1" --arg s0 "$stubs0" --arg s1 "$stubs1" --arg a "$aisvc" '{action:"clear-database deleteSourceKinds:[0] (sourceless nodes)", observed:{http_status:$st, native_before:$n0, native_after:$n1, kindless_stubs_before:$s0, kindless_stubs_after:$s1, llmhound_services_left:$a}, note:"native_after < native_before would mean the sweep deletes ingested AD/Azure nodes"}')"
}

# ---------------------------------------------------------------------------
# R2 — Cypher shape matrix and scale
# ---------------------------------------------------------------------------
r2() {
    say "--- R2 query shapes and scale"
    local ek kinds spec id what q res t0 t1
    ek=$(call GET "/api/v2/extensions-edges" | jq -c '.' | cut -c1-3000)
    # BloodHound's authoritative list of path-capable (traversable) kinds, native + extension
    kinds=$(call GET "/api/v2/extensions-edges?is_traversable=true" | jq -r '[.. | objects | select(has("name") and has("is_traversable")) | .name] | unique | join("|")' 2>/dev/null)
    record R2.0 info "$(jq -cn --arg k "$kinds" --arg st "$(last_status)" --arg raw "$ek" '{action:"GET /api/v2/extensions-edges?is_traversable=true (source for generated PATH_KINDS)", observed:{http_status:$st, kinds:$k, sample:($raw|.[0:500])}}')"
    local PK="MemberOf|HasSession|GenericAll|GenericWrite|WriteDacl|AdminTo|Contains"
    for spec in \
      "R2.1|typed multi-hop shortestPath to tier 0 from a group|MATCH (g:Group) WHERE g.objectid ENDS WITH '-513' MATCH (t:Tag_Tier_Zero) MATCH p=shortestPath((g)-[:$PK*1..]->(t)) RETURN p" \
      "R2.2|untyped shortestPath (documented as unsafe)|MATCH (g:Group) WHERE g.objectid ENDS WITH '-513' MATCH (t:Tag_Tier_Zero) MATCH p=shortestPath((g)-[*1..]->(t)) RETURN p" \
      "R2.3|P1 shape: service->host then path from Domain Users|MATCH (s:LLMHound_AIService)-[:LLMHound_ObservedAt]->(h) WHERE NOT h:LLMHound_NetworkEndpoint MATCH (g:Group) WHERE g.objectid ENDS WITH '-513' MATCH p=shortestPath((g)-[:$PK*1..]->(h)) RETURN s,h,p" \
      "R2.4|P6 shape: unattributed services|MATCH (s:LLMHound_AIService)-[:LLMHound_ObservedAt]->(n:LLMHound_NetworkEndpoint) RETURN s,n" \
      "R2.5|multi-label match on shared AIService label|MATCH (s:LLMHound_AIService) RETURN s" \
      "R2.6|array predicate any(x IN s.exec_surface ...)|MATCH (s:LLMHound_AIService) WHERE s.auth_observed IN ['anonymous','mixed'] AND any(x IN s.exec_surface WHERE x IN ['code_kernel','terminal']) RETURN s" \
      "R2.7|array membership 'x' IN s.anon_operations|MATCH (s:LLMHound_AIService) WHERE 'jupyter_contents' IN s.anon_operations RETURN s" \
      "R2.8|variable-length from host to tier 0, bounded 1..3|MATCH (s:LLMHound_AIService)-[:LLMHound_ObservedAt]->(h) WHERE NOT h:LLMHound_NetworkEndpoint MATCH p=(h)-[:$PK*1..3]->(t:Tag_Tier_Zero) RETURN s,h,p" \
      "R2.9|tier-0 by system_tags property (documented IN form)|MATCH (t) WHERE 'admin_tier_0' IN t.system_tags RETURN t" \
      "R2.10|tier-0 by system_tags CONTAINS|MATCH (t) WHERE t.system_tags CONTAINS 'admin_tier_0' RETURN t" \
      "R2.11|OPTIONAL MATCH attached host|MATCH (s:LLMHound_AIService) OPTIONAL MATCH (s)-[:LLMHound_ObservedAt]->(h) RETURN s,h" \
      "R2.12|native kind in edge type union with extension kind|MATCH p=(s:LLMHound_AIService)-[:LLMHound_ObservedAt|LLMHound_CanExecuteOn]->(h:Computer) RETURN p" \
      "R2.13|ORDER BY length(p) with shortestPath|MATCH (a:Computer) MATCH (t:Tag_Tier_Zero) MATCH p=shortestPath((a)-[:$PK*1..]->(t)) RETURN p ORDER BY length(p) LIMIT 5" \
      "R2.30|WORKING: shortestPath, inline endpoint labels, WHERE after the pattern|MATCH p=shortestPath((g:Group)-[:$PK*1..]->(t:Tag_Tier_Zero)) WHERE g.objectid ENDS WITH '-513' RETURN p" \
      "R2.31|WORKING: shortestPath to hosts that have a service (pattern predicate in WHERE)|MATCH p=shortestPath((g:Group)-[:$PK*1..]->(h:Computer)) WHERE g.objectid ENDS WITH '-513' AND (h)<-[:LLMHound_ObservedAt]-(:LLMHound_AIService) RETURN p" \
      "R2.32|WORKING: shortestPath from one objectid to hosts that have a service|MATCH p=shortestPath((a {objectid:'$SID_LOW'})-[:$PK*1..]->(h:Computer)) WHERE (h)<-[:LLMHound_ObservedAt]-(:LLMHound_AIService) RETURN p" \
      "R2.33|WORKING: bounded var-length with the service join (not shortestPath)|MATCH (s:LLMHound_AIService)-[:LLMHound_ObservedAt]->(h:Computer) MATCH p=(g:Group)-[:$PK*1..4]->(h) WHERE g.objectid ENDS WITH '-513' RETURN s,h,p LIMIT 100" \
      "R2.34|WORKING: service-to-tier-0 including the attachment edge|MATCH p=shortestPath((s:LLMHound_AIService)-[:LLMHound_ObservedAt|$PK*1..]->(t:Tag_Tier_Zero)) WHERE s.auth_observed = 'anonymous' RETURN p" \
      "R2.35|FAILS: ORDER BY size(relationships(p))|MATCH (s:LLMHound_AIService)-[:LLMHound_ObservedAt]->(h:Computer) MATCH p=(g:Group)-[:$PK*1..4]->(h) WHERE g.objectid ENDS WITH '-513' RETURN s,h,p ORDER BY size(relationships(p)) LIMIT 10" \
      "R2.36|FAILS: pattern predicate through EXISTS((...))|MATCH p=shortestPath((g:Group)-[:$PK*1..]->(h:Computer)) WHERE g.objectid ENDS WITH '-513' AND EXISTS((:LLMHound_AIService)-[:LLMHound_ObservedAt]->(h)) RETURN p" \
      "R2.14|size/labels function and count aggregation|MATCH (s:LLMHound_AIService) RETURN count(s)"; do
        IFS='|' read -r id what q <<<"$spec"
        t0=$(now_ms); res=$(qrun "$q"); t1=$(now_ms)
        record "$id" info "$(jq -cn --arg w "$what" --arg q "$q" --argjson r "$res" --arg ms "$((t1-t0))" '{action:$w, query:$q, observed:$r, elapsed_ms:($ms|tonumber)}')"
    done
    r2_scale "$PK"
}
r2b() {
    say "--- R2b full generated PATH_KINDS list"
    local PK n q res t0 t1 spec id
    PK=$(call GET /api/v2/extensions-edges | jq -r '[.data[]|select(.is_traversable)|.name]|join("|")')
    n=$(printf '%s' "$PK" | awk -F'|' '{print NF}')
    for spec in \
      "R2.40|shortestPath Domain Users -> tier 0 with the full traversable-kind list|MATCH p=shortestPath((g:Group)-[:$PK*1..]->(t:Tag_Tier_Zero)) WHERE g.objectid ENDS WITH '-513' RETURN p" \
      "R2.41|shortestPath to hosts with a service with the full list|MATCH p=shortestPath((g:Group)-[:$PK*1..]->(h:Computer)) WHERE g.objectid ENDS WITH '-513' AND (h)<-[:LLMHound_ObservedAt]-(:LLMHound_AIService) RETURN p"; do
        IFS='|' read -r id what q <<<"$spec"
        t0=$(now_ms); res=$(qrun "$q"); t1=$(now_ms)
        record "$id" info "$(jq -cn --arg w "$what" --arg n "$n" --argjson r "$res" --arg ms "$((t1-t0))" '{action:$w, kinds_in_pattern:($n|tonumber), observed:$r, elapsed_ms:($ms|tonumber)}')"
    done
}

r2_scale() {
    local PK="$1" n="${SCALE_N:-3000}" f="$WORK/scale.json" out t0 t1 res
    say "  scale: $n services attached to an existing Computer"
    python3 - "$f" "$n" "$SID_W1" <<'PY'
import json, sys, hashlib
f, n, w1 = sys.argv[1], int(sys.argv[2]), sys.argv[3]
nodes, edges = [], []
for i in range(n):
    nid = hashlib.sha256(f"scale-{i}".encode()).hexdigest().upper()
    nodes.append({"id": nid, "kinds": ["LLMHound_MCPServer", "LLMHound_AIService"],
                  "properties": {"name": f"MCP SCALE {i}", "auth_observed": "anonymous" if i % 3 == 0 else "denied",
                                 "anon_operations": ["mcp_initialize", "mcp_tools_list"] if i % 3 == 0 else [], "vantage_key": "scanner-a"}})
json.dump({"metadata": {"source_kind": "LLMHound"}, "graph": {"nodes": nodes, "edges": []}}, open(f, "w"))
link = [{"kind": "LLMHound_ObservedAt", "start": {"match_by": "id", "value": hashlib.sha256(f"scale-{i}".encode()).hexdigest().upper()},
         "end": {"match_by": "id", "value": w1}, "properties": {"match_method": "mapping"}} for i in range(n)]
json.dump({"graph": {"nodes": [], "edges": link}}, open(f.replace(".json", "-link.json"), "w"))
PY
    t0=$(now_ms); out=$(upload_json "$f" scale.json); wait_idle; t1=$(now_ms)
    record R2.20 "$(payload_ok "$out" | sed 's/true/pass/;s/false/fail/')" "$(jq -cn --argjson o "$out" --arg ms "$((t1-t0))" --arg n "$n" '{action:"ingest N service nodes", n:$n, observed:$o, elapsed_ms:($ms|tonumber)}')"
    t0=$(now_ms); out=$(upload_json "${f%.json}-link.json" scale-link.json); wait_idle; t1=$(now_ms)
    record R2.21 "$(payload_ok "$out" | sed 's/true/pass/;s/false/fail/')" "$(jq -cn --argjson o "$out" --arg ms "$((t1-t0))" --arg n "$n" '{action:"ingest N sourceless linking edges to one Computer", n:$n, observed:$o, elapsed_ms:($ms|tonumber)}')"
    t0=$(now_ms); res=$(qrun "MATCH p=shortestPath((g:Group)-[:$PK*1..]->(h:Computer)) WHERE g.objectid ENDS WITH '-513' AND (h)<-[:LLMHound_ObservedAt]-(:LLMHound_AIService) RETURN p"); t1=$(now_ms)
    record R2.22 info "$(jq -cn --argjson r "$res" --arg ms "$((t1-t0))" '{action:"shortestPath to a Computer with 3000 attached services (working P1 shape)", observed:$r, elapsed_ms:($ms|tonumber)}')"
    t0=$(now_ms); res=$(qrun "MATCH (s:LLMHound_AIService) WHERE s.auth_observed = 'anonymous' RETURN s"); t1=$(now_ms)
    record R2.23 info "$(jq -cn --argjson r "$res" --arg ms "$((t1-t0))" '{action:"property filter over N services, no LIMIT", observed:$r, elapsed_ms:($ms|tonumber)}')"
    t0=$(now_ms); res=$(qrun "MATCH (s:LLMHound_AIService)-[:LLMHound_ObservedAt]->(h:Computer) MATCH p=(g:Group)-[:$PK*1..4]->(h) WHERE g.objectid ENDS WITH '-513' RETURN s,h,p LIMIT 100"); t1=$(now_ms)
    record R2.24 info "$(jq -cn --argjson r "$res" --arg ms "$((t1-t0))" '{action:"bounded join+var-length over 3000 services, LIMIT 100", observed:$r, elapsed_ms:($ms|tonumber)}')"
}

# __SECTIONS_BEFORE_THIS_LINE__
main "$@"
