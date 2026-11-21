#!/usr/bin/env bash
# Shared helpers for the LLMHound M0 lab scripts. Source, don't execute.
# All helpers operate against the local loopback lab only.

set -u

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNTIME_DIR="$LAB_DIR/.runtime"
RESULTS_DIR="$RUNTIME_DIR/results"
FIXTURES_DIR="$LAB_DIR/fixtures"

# lab.env-derived settings (loaded by lab-up.sh into .env)
BHE_URL="${BHE_URL:-http://127.0.0.1:${BHE_PORT:-18080}}"
BHE_USER="${BHE_USER:-admin}"

load_lab_env() {
    # shellcheck disable=SC1091
    [ -f "$LAB_DIR/.env" ] && set -a && . "$LAB_DIR/.env" && set +a
    BHE_URL="${BHE_URL:-http://127.0.0.1:${BHE_PORT:-18080}}"
}

require_tools() {
    for t in docker curl jq; do
        command -v "$t" >/dev/null 2>&1 || { echo "missing tool: $t" >&2; return 1; }
    done
}

# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

bh_login() {
    # Exchanges the lab admin password (kept in the untracked .env) for a
    # session token stored only in .runtime (gitignored).
    mkdir -p "$RUNTIME_DIR"
    local secret
    secret="${POSTGRES_PASSWORD:?POSTGRES_PASSWORD missing (run lab-up.sh)}"
    local resp
    resp=$(curl -sS -X POST "$BHE_URL/api/v2/login" \
        -H 'Content-Type: application/json' \
        -w '\n%{http_code}' \
        -d "{\"login_method\":\"secret\",\"username\":\"$BHE_USER\",\"secret\":\"$secret\"}")
    local status body
    status=$(printf '%s' "$resp" | tail -n1)
    body=$(printf '%s' "$resp" | sed '$d')
    if [ "$status" != "200" ]; then
        echo "login failed (HTTP $status): $body" >&2
        return 1
    fi
    printf '%s' "$body" | jq -r '.data.session_token' > "$RUNTIME_DIR/token"
    chmod 600 "$RUNTIME_DIR/token"
}

bh_token() {
    if [ ! -s "$RUNTIME_DIR/token" ]; then
        load_lab_env
        bh_login
    fi
    cat "$RUNTIME_DIR/token"
}

# ---------------------------------------------------------------------------
# API calls
# ---------------------------------------------------------------------------

# api METHOD PATH [BODY] — low-level: prints HTTPSTATUS:<code> as the first
# line followed by the response body.
api() {
    local method="$1" path="$2" body="${3:-}"
    local args=(-sS -X "$method" "$BHE_URL$path"
        -H "Authorization: Bearer $(bh_token)"
        -H 'Accept: application/json'
        -w '\n%{http_code}')
    if [ -n "$body" ]; then
        args+=(-H 'Content-Type: application/json' -d "$body")
    fi
    local resp
    resp=$(curl "${args[@]}") || { printf 'HTTPSTATUS:000\ncurl failed\n'; return 1; }
    local status
    status=$(printf '%s' "$resp" | tail -n1)
    printf 'HTTPSTATUS:%s\n' "$status"
    printf '%s' "$resp" | sed '$d'
}

# call METHOD PATH [BODY] — caller-facing: prints the body; records the HTTP
# status in RUNTIME_DIR/api_status (command substitution would lose a global,
# so the status goes through a file). Use `last_status` to read it.
call() {
    local out
    mkdir -p "$RUNTIME_DIR"
    out=$(api "$@") || { printf '%s' 000 > "$RUNTIME_DIR/api_status"; return 1; }
    local status
    status=$(printf '%s' "$out" | sed -n 's/^HTTPSTATUS://p' | head -1)
    printf '%s' "${status:-000}" > "$RUNTIME_DIR/api_status"
    printf '%s' "$(printf '%s' "$out" | tail -n +2)"
}

last_status() { cat "$RUNTIME_DIR/api_status"; }

# api_raw FILE CONTENT_TYPE PATH — low-level raw-body upload, same protocol.
api_raw() {
    local file="$1" ctype="$2" path="$3"
    shift 3
    local resp extra_args=("$@")
    local base=(-sS -X POST "$BHE_URL$path"
        -H "Authorization: Bearer $(bh_token)"
        -H "Content-Type: $ctype")
    if [ "${#extra_args[@]}" -gt 0 ]; then
        base+=("${extra_args[@]}")
    fi
    resp=$(curl "${base[@]}" \
        --data-binary "@$file" \
        -w '\n%{http_code}') || { printf 'HTTPSTATUS:000\ncurl failed\n'; return 1; }
    local status
    status=$(printf '%s' "$resp" | tail -n1)
    printf 'HTTPSTATUS:%s\n' "$status"
    printf '%s' "$resp" | sed '$d'
}

# call_raw FILE CONTENT_TYPE PATH [extra curl args] — caller-facing: prints
# the body; records the HTTP status like `call` does.
call_raw() {
    local file="$1" ctype="$2" path="$3"
    shift 3
    local out
    mkdir -p "$RUNTIME_DIR"
    if [ "$#" -gt 0 ]; then
        out=$(api_raw "$file" "$ctype" "$path" "$@") || { printf '%s' 000 > "$RUNTIME_DIR/api_status"; return 1; }
    else
        out=$(api_raw "$file" "$ctype" "$path") || { printf '%s' 000 > "$RUNTIME_DIR/api_status"; return 1; }
    fi
    local status
    status=$(printf '%s' "$out" | sed -n 's/^HTTPSTATUS://p' | head -1)
    printf '%s' "${status:-000}" > "$RUNTIME_DIR/api_status"
    printf '%s' "$(printf '%s' "$out" | tail -n +2)"
}

# cypher QUERY [INCLUDE_PROPS] — runs a read query via the API. Prints body.
cypher() {
    local query="$1" props="${2:-true}"
    call POST /api/v2/graphs/cypher \
        "$(jq -cn --arg q "$query" --arg p "$props" '{query: $q, include_properties: ($p == "true")}')"
}

# cypher_count CYPHER — number of result nodes, or -1 on any error.
cypher_count() {
    local out
    out=$(cypher "$1") || { echo -1; return; }
    if [ "$(last_status)" != "200" ]; then echo -1; return; fi
    printf '%s' "$out" | jq -r '.data.nodes | length' 2>/dev/null || echo -1
}

# ---------------------------------------------------------------------------
# Uploads (job-based flow)
# ---------------------------------------------------------------------------

# upload_and_wait FILE CONTENT_TYPE NAME [POLL_SECS] — full job flow.
# Prints "<upload_status> <final_job_status>" where upload_status is the HTTP
# status of the /end call. Sets UPLOAD_JOB_ID.
upload_and_wait() {
    local file="$1" ctype="$2" name="$3" timeout="${4:-180}"
    local resp
    UPLOAD_JOB_ID=""
    resp=$(call POST /api/v2/file-upload/start) || return 1
    if [ "$(last_status)" != "201" ]; then
        echo "file-upload/start failed (HTTP $(last_status)): $resp" >&2
        return 1
    fi
    UPLOAD_JOB_ID=$(printf '%s' "$resp" | jq -r '.data.id')

    resp=$(call_raw "$file" "$ctype" "/api/v2/file-upload/$UPLOAD_JOB_ID" \
        -H "X-File-Upload-Name: $name")
    if [ "$(last_status)" != "202" ]; then
        echo "file upload failed (HTTP $(last_status)): $resp" >&2
        return 1
    fi

    resp=$(call POST "/api/v2/file-upload/$UPLOAD_JOB_ID/end")
    case "$(last_status)" in
        200|202) : ;;
        *) echo "file-upload/end failed (HTTP $(last_status)): $resp" >&2; return 1 ;;
    esac

    # Ingest is asynchronous; poll the job status until complete/canceled.
    local waited=0 st
    while [ "$waited" -lt "$timeout" ]; do
        # Observed job-status values: 0 ready, 1 running, 2 complete, 3 canceled,
        # 8 (partial failure: some files failed; recorded as terminal here).
        st=$(call GET /api/v2/file-upload | jq -r --arg id "$UPLOAD_JOB_ID" '
            first(.data[] | select(.id == ($id | tonumber))).status // "gone"')
        case "$st" in
            2|3|8|gone) printf '%s %s\n' "ok" "$st"; return 0 ;;
        esac
        sleep 2
        waited=$((waited + 2))
    done
    echo "timeout job_status=$st"
    return 1
}

# ---------------------------------------------------------------------------
# Result recording (one JSON line per check)
# ---------------------------------------------------------------------------

record() {
    # record ID VERDICT SUMMARY_JSON  (summary is a compact JSON object)
    mkdir -p "$RESULTS_DIR"
    local line
    line=$(jq -cn --arg id "$1" --arg verdict "$2" --argjson obs "$3" \
        --arg ts "$(date -u +%FT%TZ)" \
        '{id: $id, verdict: $verdict, observed: $obs, at: $ts}')
    echo "$line" >> "${RESULTS_FILE:-$RESULTS_DIR/m0-checks.jsonl}"
    printf '%-8s %s\n' "$2" "$1"
}

brief_http() {
    # Brief evidence string from an HTTP status + body.
    jq -cn --arg s "$(last_status)" --arg b "$(printf '%s' "$1" | tr -d '\n' | cut -c1-400)" \
        '{http_status: $s, body: $b}'
}

# ---------------------------------------------------------------------------
# Shared check helpers (used by run-m0-checks.sh and run-r-checks.sh)
# ---------------------------------------------------------------------------

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
    while [ "$waited" -lt "${UPLOAD_WAIT:-300}" ]; do
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
