#!/usr/bin/env bash
# Offline fixture validation for the M0 lab (no network, no lab required).
#
# Checks every checked-in payload and extension schema against the structure
# rules documented for OpenGraph (developer/nodes, developer/edges,
# developer/metadata, developer/graph-definition pages, CE 9.x docs).
#
# fixtures/payloads/*.json and fixtures/extension/*.json must be VALID.
# fixtures/{payloads,extension}/negative/*.json must be INVALID (they are the
# probes we expect BloodHound to reject; if one validates clean, fix the
# fixture so it actually exercises the rejection path).
set -uo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail=0

ok()   { printf '  ok    %s\n' "$1"; }
bail() { printf '  FAIL  %s\n' "$1" >&2; fail=1; }

payload_errors() {
    # Prints one error line per structural problem found in a payload file.
    local file="$1"
    jq -re '
      (keys | sort | join(",")) as $top |
      (if (($top | contains("graph")) | not) then "missing graph object" else empty end),
      (if ($top | contains("metadata")) and ((.metadata | type) != "object") then "metadata not an object" else empty end),
      (if ($top | contains("metadata")) and (((.metadata | keys) - ["source_kind"] | length) > 0)
        then "metadata has keys other than source_kind" else empty end),
      (.graph.nodes | type) as $nt |
      (if $nt != "array" then "graph.nodes is not an array" else empty end),
      (.graph.edges | type) as $et |
      (if $et != "array" then "graph.edges is not an array" else empty end)
      | select(. != "")
    ' "$file" 2>/dev/null | head -10
    jq -re '
      def hetero: type=="array" and (((map(type) | unique | length) > 1) or any(.[]; ((type != "string") and (type != "number") and (type != "boolean"))));
      def builtin_kind: ascii_downcase as $k |
        $k == "computer" or $k == "user" or $k == "group" or $k == "domain";
      .graph.nodes[]? | (.id // "") as $id |
      (
        (if ($id | type) != "string" then "node id not a string" else empty end),
        (if ($id | test(":")) then "node id contains colon: \($id)" else empty end),
        (if ((.kinds // []) | length) > 3 then "node \($id): more than 3 kinds" else empty end),
        (if any((.kinds // [])[]?; type != "string") then "node \($id): non-string kind" else empty end),
        (if any((.kinds // [])[]?; test("^tag[_]"; "i")) then "node \($id): reserved tag_ kind prefix" else empty end),
        (if any((.kinds // [])[]?; builtin_kind) then "node \($id): built-in kind overlap" else empty end),
        ((.properties // {}) | to_entries[]? |
          (
            (if (.value|type) == "object" then "node \($id): nested-object property \(.key)" else empty end),
            (if (.value|type) == "null" then "node \($id): null property \(.key)" else empty end),
            (if (.value|hetero) then "node \($id): heterogeneous array \(.key)" else empty end),
            (if (.key|ascii_downcase) == "objectid" then "node \($id): reserved property objectid" else empty end)
          ))
      )
      | select(. != "")
    ' "$file" 2>/dev/null | head -10
    jq -re '
      (.graph.nodes[]? | .properties // {} | to_entries[]?
        | select((.value|type)=="object" or (.value|type)=="null"
                 or (.value|hetero)
                 or (.key|ascii_downcase) == "objectid")
        | .key) | "reserved/invalid property: \(.)"
    ' "$file" 2>/dev/null | sort -u | head -10
    jq -re '
      .graph.edges[]? |
      (if ((.kind // "") | test("^[A-Za-z0-9_]+$") | not)
        then "edge kind not ^[A-Za-z0-9_]+$: \(.kind // "<missing>")" else empty end),
      (if (.kind // "") | test("^tag[_]"; "i") then "edge \(.kind): reserved tag_ prefix" else empty end),
      (.start // {}) as $s | (.end // {}) as $e |
      ($s.match_by // "id") as $sm | ($e.match_by // "id") as $em |
      (if (.kind // "") == "" then "edge missing kind" else empty end),
      (if ($sm == "property") and ((($s.property_matchers // []) | length) < 1)
        then "edge \(.kind): start property match without matchers" else empty end),
      (if ($sm == "property") and ($s | has("value"))
        then "edge \(.kind): start property match with value" else empty end),
      (if ($sm != "property") and (($s.value // null) == null)
        then "edge \(.kind): start id/name match without value" else empty end),
      (if ($em == "property") and ((($e.property_matchers // []) | length) < 1)
        then "edge \(.kind): end property match without matchers" else empty end),
      (if ($em == "property") and ($e | has("value"))
        then "edge \(.kind): end property match with value" else empty end),
      (if ($em != "property") and (($e.value // null) == null)
        then "edge \(.kind): end id/name match without value" else empty end),
      (if any(($s.property_matchers // [])[]?; ((.operator // "") != "equals"))
        then "edge \(.kind): start matcher operator not equals" else empty end),
      (if any(($e.property_matchers // [])[]?; ((.operator // "") != "equals"))
        then "edge \(.kind): end matcher operator not equals" else empty end)
      | select(. != "")
    ' "$file" 2>/dev/null | head -10
}

schema_errors() {
    local file="$1"
    local ns
    ns=$(jq -r '.schema.namespace // ""' "$file" 2>/dev/null)
    jq -re --arg ns "$ns" '
      (if ((.schema.name // "") == "") then "schema.name missing" else empty end),
      (if ((.schema.display_name // "") == "") then "schema.display_name missing" else empty end),
      (if ((.schema.version // "") | test("^v[0-9]+\\.[0-9]+\\.[0-9]+$") | not)
        then "schema.version not vX.Y.Z" else empty end),
      (if ($ns == "") then "schema.namespace missing" else empty end),
      ([.node_kinds[]?.name, .relationship_kinds[]?.name][] |
        (if (startswith($ns + "_") | not) then "kind not namespace-prefixed: \(.)" else empty end),
        (if (length <= ($ns | length) + 1) then "kind is prefix only: \(.)" else empty end),
        (if test("^tag[_]"; "i") then "kind reserved tag_ prefix: \(.)" else empty end)
      ),
      (.relationship_kinds[]? |
        (if (has("is_traversable") | not) or (.is_traversable|type != "boolean")
          then "relationship kind without boolean is_traversable: \(.name)" else empty end))
      | select(. != "")
    ' "$file" 2>/dev/null | sort -u | head -10
}

echo "payloads (must validate):"
for f in "$LAB_DIR"/fixtures/payloads/*.json; do
    [ -e "$f" ] || continue
    errs=$(payload_errors "$f")
    [ -z "$errs" ] && ok "$(basename "$f")" || bail "$(basename "$f"): $(echo "$errs" | head -2)"
done
echo "payloads (must be rejected by validation):"
for f in "$LAB_DIR"/fixtures/payloads/negative/*.json; do
    [ -e "$f" ] || continue
    errs=$(payload_errors "$f")
    [ -n "$errs" ] && ok "$(basename "$f")" || bail "$(basename "$f"): unexpectedly valid"
done
echo "extension schemas (must validate):"
for f in "$LAB_DIR"/fixtures/extension/*.json; do
    [ -e "$f" ] || continue
    errs=$(schema_errors "$f")
    [ -z "$errs" ] && ok "$(basename "$f")" || bail "$(basename "$f"): $(echo "$errs" | head -2)"
done
echo "extension schemas (must be rejected by validation):"
for f in "$LAB_DIR"/fixtures/extension/negative/*.json; do
    [ -e "$f" ] || continue
    errs=$(schema_errors "$f")
    [ -n "$errs" ] && ok "$(basename "$f")" || bail "$(basename "$f"): unexpectedly valid"
done

if [ "$fail" -ne 0 ]; then
    echo "fixture validation FAILED" >&2
    exit 1
fi
echo "all fixtures valid"
