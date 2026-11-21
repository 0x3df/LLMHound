# Starter saved queries

> **Status: P1, P2, P4 and P6 are built and validated** (`extension/saved_searches/`, generated;
> `lab/scripts/run-d2-checks.sh`). The rest are planned. These queries ship in `extension/saved_searches/` in
> SpecterOps Query Library format. Their shapes were validated on CE 9.7.1
> ([R2](05-ce-compatibility.md#follow-up-answers-for-the-tier-0-redesign-r1r9));
> kind and property names follow the [graph model](02-graph-model.md) and the
> [M0 findings](05-ce-compatibility.md). Every property a query filters on is a
> flat graph property, not sidecar-only data.

## Conventions

- **Emitted kind names.** The examples below use clean logical names for
  readability. CE 9.7.1 requires the `LLMHound_` namespace prefix
  ([M0 Q1](05-ce-compatibility.md)), so the shipped files are generated with
  emitted names (`LLMHound_AIService`, `LLMHound_ObservedAt`,
  `LLMHound_NetworkEndpoint`, ...) from `internal/graph/kinds.go`; native kinds
  (`Computer`, `Group`, ...) stay unqualified. Property names are lowercase.
- **Import format.** Shipped as `{name, query, description}` JSON files (zipped)
  for `POST /api/v2/saved-queries/import` (M0 Q9).
- **Product questions.** The first group answers the tier-0 pathing questions
  this project exists for. They are the acceptance spine for the property
  contract.
- **`<PATH_KINDS>`.** Raw Cypher traverses every edge kind, regardless of any
  non-traversable flag, so path patterns must name kinds explicitly and never use
  an untyped `[*1..]` (it would walk `ObservedAt` and other context edges).
  The list is **generated, not hand-maintained**: `GET /api/v2/extensions-edges`
  returns every kind with `is_traversable` and `schema_name`; filter it
  client-side (its query parameters are ignored) to the traversable kinds
  (107 on the pinned lab, AD and Azure included). A pattern with all 107 ran in
  about 60 ms ([R2](05-ce-compatibility.md#follow-up-answers-for-the-tier-0-redesign-r1r9)).
  `LLMHound_CanExecuteOn` appears in that list only when it is registered
  traversable, i.e. when a [path-qualification](02-graph-model.md#path-qualification-traversable-edges)
  rule is enabled. The lab fixture has no `AdminTo`, so do not hard-code any
  specific AD edge.
- **Shipped form.** The shipped files differ from the readable examples below: no
  `NOT h:NetworkEndpoint` host filter is needed because the `ObservedAt` pattern predicate
  and an unlabeled `shortestPath` endpoint work for any native host kind, and P2's start is
  the `<START_OBJECTID>` placeholder. See `extension/saved_searches/README.md`.
- **Query shapes that work on CE 9.7.1.** (R2) `shortestPath` endpoints must be
  inline in the pattern with the filter in a trailing `WHERE`; endpoints bound by
  an earlier `MATCH` fail with HTTP 500. To require a service on the target host,
  use a pattern predicate in that `WHERE`. `length(p)` and
  `size(relationships(p))` are unavailable, so ranking by path length is done with
  the shortest-path API, one start and one end node at a time. Results are capped
  near 1,000 nodes, so every query that can return many rows has a `LIMIT`.
- **`AIService` label.** Carried by every concrete service kind, including
  `MCPServer` and `A2AAgent`. M0 Q2 and R2 confirmed multi-label support in CE 9.7.1,
  so queries filter on `LLMHound_AIService`.
- **Attached host.** `h` is any existing node a service is attached to
  (`Computer`, `AZVM`, …); the `WHERE NOT h:NetworkEndpoint` filter excludes
  unmapped targets.
- **Start sets.** `$start` is a node, owned principals, or Domain Users
  (`objectid ENDS WITH '-513'`). Tier 0 is the label
  `Tag_Tier_Zero` ([R1](05-ce-compatibility.md#follow-up-answers-for-the-tier-0-redesign-r1r9);
  `system_tags` is a string, so `IN n.system_tags` fails).
- Access facts are properties: `anon_operations` is an array of check IDs that
  succeeded anonymously, using the collectors' real IDs (`mcp_initialize`,
  `mcp_tools_list`, `jupyter_contents`, `jupyter_sessions`, `ollama_tags`, ...).
  Only enumeration-class checks count; Jupyter version metadata never does.

## Tier-0 pathing questions

### P1. Hosts running AI or MCP services that sit on an attack path

```cypher
MATCH p = shortestPath((g:Group)-[:<PATH_KINDS>*1..]->(h:Computer))
WHERE g.objectid ENDS WITH '-513'
  AND (h)<-[:ObservedAt]-(:AIService)
RETURN p
LIMIT 100
```

`h:Computer` illustrates a single native host kind; the shipped generated
queries leave `h` unlabeled (`->(h)`), because the `ObservedAt` pattern
predicate matches any mapped native host kind (`Computer`, `AZVM`, ...) in one
query. The path shows the route; the services on each host come from P4 or the
entity panel (a `shortestPath` endpoint cannot also bind the service, see the
shape rules above).

### P2. Shortest path from an asset to any AI host

```cypher
MATCH p = shortestPath((a {objectid: $start})-[:<PATH_KINDS>*1..]->(h:Computer))
WHERE (h)<-[:ObservedAt]-(:AIService)
RETURN p
LIMIT 25
```

To rank hosts by distance, run the Cypher above and then the shortest-path API
(`/api/v2/graphs/shortest-path`) per host, or read the path lengths client-side.

### P3. AI hosts one or two hops from tier 0

```cypher
MATCH (s:AIService)-[:ObservedAt]->(h:Computer)
MATCH p = (h)-[:<PATH_KINDS>*1..2]->(t:Tag_Tier_Zero)
RETURN s, h, p
LIMIT 100
```

### P4. Anonymously reachable AI services that expose an execution surface

```cypher
MATCH (s:AIService)-[:ObservedAt]->(h)
WHERE NOT h:NetworkEndpoint
  AND s.auth_observed IN ['anonymous', 'mixed']
  AND any(x IN s.exec_surface WHERE x IN ['code_kernel','terminal','job_submit','code_eval','workflow_exec','tool_invocation'])
RETURN s, h
```

Combine with P2 to ask for the shortest path to such a host. Execution-surface
values are labeled `observed`, `declared`, or `inferred` in
`exec_surface_basis`; this query does not claim execution was demonstrated.

### P5. Gateways and UIs whose backends sit on a different host

```cypher
MATCH (s:AIService)-[:UsesBackend]->(b:AIService)
MATCH (s)-[:ObservedAt]->(hs), (b)-[:ObservedAt]->(hb)
WHERE hs <> hb AND NOT hs:NetworkEndpoint AND NOT hb:NetworkEndpoint
RETURN s, hs, b, hb
```

### P6. Unattributed AI services (hand-off list for the normalizer)

```cypher
MATCH (s:AIService)-[:ObservedAt]->(n:NetworkEndpoint)
RETURN s, n
```

### P7. MCP tools with high-risk capability hints on reachable hosts

```cypher
MATCH (m:MCPServer)-[:ProvidesTool]->(t:MCPTool)
WHERE any(x IN t.capability_hint WHERE x IN ['shell','filesystem','secrets','code'])
MATCH (m)-[:ObservedAt]->(h)
WHERE NOT h:NetworkEndpoint
RETURN m, t, h
```

`capability_hint` is a heuristic over advertised descriptions (`declared`); it
prioritizes review, it is not evidence of behavior.

### P8. AI hosts with an exposed secret, on a path

```cypher
MATCH (s:AIService)-[:ObservedAt]->(h:Computer)
WHERE s.has_exposed_secret = true AND s.secret_last_confirmed >= $cutoff
MATCH p = (g:Group)-[:<PATH_KINDS>*1..4]->(h)
WHERE g.objectid ENDS WITH '-513'
RETURN s, h, p
LIMIT 100
```

`has_exposed_secret` is only ever `true` or unset (high-precision match), and CE
never clears it ([R6](05-ce-compatibility.md#follow-up-answers-for-the-tier-0-redesign-r1r9)),
so the query also requires a recent `secret_last_confirmed` (`$cutoff` is an
ISO-8601 UTC string; string comparison works). A result is a confirmed presence;
a miss is not evidence of absence. The path is bounded variable-length, not
`shortestPath`, because the service is joined first.

## Inventory and posture

### I1. Anonymous access to AI services

```cypher
MATCH (s:AIService)
WHERE s.auth_observed IN ['anonymous', 'mixed']
RETURN s
```

### I2. MCP servers with anonymously listable tools

```cypher
MATCH (m:MCPServer)-[:ProvidesTool]->(t:MCPTool)
WHERE 'mcp_tools_list' IN m.anon_operations
RETURN m, t
```

### I3. Jupyter servers with anonymous API or contents access

```cypher
MATCH (j:JupyterServer)
WHERE 'jupyter_contents' IN j.anon_operations
   OR 'jupyter_sessions' IN j.anon_operations
OPTIONAL MATCH (j)-[:Contains]->(f:WorkspaceFile)
RETURN j, f
```

### I4. Model runtimes with anonymously listed models

```cypher
MATCH (s:AIService)-[:ProvidesModel]->(m:AIModel)
WHERE s.auth_observed IN ['anonymous', 'mixed']
RETURN s, m
```

### I5. Vector stores and registries exposing inventory

```cypher
MATCH (s:AIService)-[:Contains]->(r)
WHERE r:VectorCollection OR r:ModelArtifact OR r:ArtifactStore
RETURN s, r
```

### I6. AI services with TLS verification failures

```cypher
MATCH (s:AIService)
WHERE s.tls_verification = 'failed'
RETURN s
```

### I7. Services by product and version (for downstream CVE joins)

```cypher
MATCH (s:AIService)
RETURN s.product, s.software_version, count(s)
ORDER BY count(s) DESC
```
