# Starter saved queries

> **Status: planned.** These queries ship in `extension/saved_searches/` in
> SpecterOps Query Library format. Kind and property names follow the
> [graph model](graph-model.md) and may be adjusted by the
> [M0 findings](ce-compatibility.md). Every property a query filters on is a
> flat graph property, not sidecar-only data.

## Conventions

- **Emitted kind names.** The examples below use clean logical names for
  readability. CE 9.7.1 requires the `LLMHound_` namespace prefix
  ([M0 Q1](ce-compatibility.md)), so the shipped files are generated with
  emitted names (`LLMHound_AIService`, `LLMHound_ObservedAt`,
  `LLMHound_NetworkEndpoint`, ...) from `internal/graph/kinds.go`; native kinds
  (`Computer`, `Group`, ...) stay unqualified. Property names are lowercase.
- **Import format.** Shipped as `{name, query, description}` JSON files (zipped)
  for `POST /api/v2/saved-queries/import` (M0 Q9).
- **Product questions.** The first group answers the tier-0 pathing questions
  this project exists for. They are the acceptance spine for the property
  contract.
- **`<PATH_KINDS>`.** Raw Cypher traverses every edge kind, regardless of any
  non-traversable flag, so path patterns must name the AD/Azure kinds
  explicitly and never use an untyped `[*1..]`. The shipped files are
  generated from one maintained list. Representative AD kinds:
  `MemberOf|HasSession|AdminTo|CanRDP|CanPSRemote|ExecuteDCOM|SQLAdmin|AllowedToDelegate|AllowedToAct|GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns|AddMember|ForceChangePassword|AllExtendedRights`;
  Azure kinds are appended. M0 validates the list, tier-0 tag semantics, and
  performance on the pinned CE. If a rule from
  [path qualification](graph-model.md#path-qualification-traversable-edges) is
  enabled, `CanExecuteOn` is added to the list.
- **`AIService` label.** Carried by every concrete service kind, including
  `MCPServer` and `A2AAgent`. If M0 shows multi-label is unsupported, queries
  are generated with explicit kind checks.
- **Attached host.** `h` is any existing node a service is attached to
  (`Computer`, `AZVM`, …); the `WHERE NOT h:NetworkEndpoint` filter excludes
  unmapped targets.
- **Start sets.** `$start` is a node, owned principals, or Domain Users
  (`objectid ENDS WITH '-513'`). Tier 0 is the CE tag
  (`'admin_tier_0' IN n.system_tags`; verify in M0).
- Access facts are properties: `anon_operations` is an array of succeeded
  `check_id`s. The IDs below are illustrative until fixed by the collector tests.

## Tier-0 pathing questions

### P1. Hosts running AI or MCP services that sit on an attack path

```cypher
MATCH (s:AIService)-[:ObservedAt]->(h)
WHERE NOT h:NetworkEndpoint
MATCH (g:Group) WHERE g.objectid ENDS WITH '-513'
MATCH p = shortestPath((g)-[:<PATH_KINDS>*1..]->(h))
RETURN s, h, p
LIMIT 100
```

### P2. Shortest path from an asset to any AI host

```cypher
MATCH (a {objectid: $start})
MATCH (s:AIService)-[:ObservedAt]->(h)
WHERE NOT h:NetworkEndpoint AND h <> a
MATCH p = shortestPath((a)-[:<PATH_KINDS>*1..]->(h))
RETURN s, h, p
ORDER BY length(p)
LIMIT 25
```

### P3. AI hosts one or two hops from tier 0

```cypher
MATCH (s:AIService)-[:ObservedAt]->(h)
WHERE NOT h:NetworkEndpoint
MATCH p = (h)-[:<PATH_KINDS>*1..2]->(t)
WHERE 'admin_tier_0' IN t.system_tags
RETURN s, h, p
LIMIT 100
```

### P4. Anonymously reachable AI services that expose an execution surface

```cypher
MATCH (s:AIService)-[:ObservedAt]->(h)
WHERE NOT h:NetworkEndpoint
  AND s.auth_observed IN ['anonymous', 'mixed']
  AND any(x IN s.exec_surface WHERE x IN ['code_kernel','terminal','job_submit','code_eval','workflow_exec'])
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
MATCH (s:AIService)-[:ObservedAt]->(h)
WHERE NOT h:NetworkEndpoint AND s.has_exposed_secret = true
MATCH (g:Group) WHERE g.objectid ENDS WITH '-513'
MATCH p = shortestPath((g)-[:<PATH_KINDS>*1..]->(h))
RETURN s, h, p
LIMIT 100
```

`has_exposed_secret` is only ever `true` or unset (high-precision match). A
result is a confirmed presence; a miss is not evidence of absence.

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
WHERE 'mcp.tools.list' IN m.anon_operations
RETURN m, t
```

### I3. Jupyter servers with anonymous API or contents access

```cypher
MATCH (j:JupyterServer)
WHERE 'jupyter.api.status' IN j.anon_operations
   OR 'jupyter.contents.list' IN j.anon_operations
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
