# Starter saved queries

> **Status: planned.** These queries ship in `extension/saved_searches/` in
> SpecterOps Query Library format (M3). Kind and property names follow the
> [graph model](graph-model.md) and may be adjusted by the M0
> [compatibility findings](ce-compatibility.md). The properties these queries
> filter on must be flat, queryable graph properties rather than values that
> live only in the evidence sidecar.

Every relationship below is non-traversable. These queries join and filter
evidence; they are not pathfinding.

## 1. AI services on Computers reachable from existing AD attack paths

This query is the main reason LLMHound correlates with existing Computers. It
finds AI services on machines that an existing AD attack path already reaches.

```cypher
MATCH (s:AIService)-[:ObservedAt]->(c:Computer)
MATCH p = shortestPath((u:User)-[*1..]->(c))
WHERE u <> c
RETURN s, c, p
LIMIT 100
```

A tighter variant starts from a group (e.g. Domain Users) or from owned
principals.

## 2. Anonymous access to AI services, by collection vantage

```cypher
MATCH (v:CollectionVantage)-[a:UnauthenticatedAccess]->(s:AIService)
RETURN v, a, s
```

## 3. MCP servers with anonymously listable tools

```cypher
MATCH (v:CollectionVantage)-[:UnauthenticatedAccess]->(m:MCPServer)-[:ProvidesTool]->(t:MCPTool)
RETURN v, m, t
```

## 4. Jupyter servers with anonymous API or contents access

```cypher
MATCH (v:CollectionVantage)-[:UnauthenticatedAccess]->(j:JupyterServer)
OPTIONAL MATCH (j)-[:Contains]->(f:WorkspaceFile)
RETURN v, j, f
```

## 5. Model runtimes with anonymously listed models

```cypher
MATCH (v:CollectionVantage)-[:UnauthenticatedAccess]->(s:AIService)-[:ProvidesModel]->(m:AIModel)
RETURN v, s, m
```

## 6. Gateways and UIs with reported backends

```cypher
MATCH (s:AIService)-[:UsesBackend]->(b:AIService)
RETURN s, b
```

## 7. Vector stores and registries exposing inventory

```cypher
MATCH (s:AIService)-[:Contains]->(r)
WHERE r:VectorCollection OR r:ModelArtifact OR r:ArtifactStore
RETURN s, r
```

## 8. AI services with TLS verification failures

```cypher
MATCH (s:AIService)
WHERE s.tls_verification = 'failed'
RETURN s
```

## 9. Uncorrelated AI services (not attached to an AD Computer)

Use this query to find gaps in coverage. Uncorrelated targets need a
mapping-file entry or a domain suffix.

```cypher
MATCH (s:AIService)-[:ObservedAt]->(n:NetworkEndpoint)
RETURN s, n
```
