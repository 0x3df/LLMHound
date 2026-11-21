# MCP collector

Anonymous, read-only enumeration of Model Context Protocol servers over network
transports. Package: `internal/collectors/mcp`. Contract: the MCP row of the
[capability matrix](../03-collector-capabilities.md).

## Behavior

- **Transports:** Streamable HTTP, with a legacy SSE fallback (chosen automatically, or by
  `Transport: streamable | sse`; an endpoint ending in `/sse` is tried as SSE first). stdio
  servers are out of scope.
- **Anonymous only:** no credentials are sent. The protocol session is initialized, then only
  list operations are issued. No tool is called, no prompt is rendered, and **no resource
  content is read**; resource listing is inventory, not permission to read.
- **On HTTP 401:** the collector records the denial and, where available, fetches the anonymous
  RFC 9728 protected-resource metadata (`/.well-known/oauth-protected-resource`) to record the
  advertised authorization server(s). Those URLs are recorded, never followed. On 403 the
  RFC 9728 check is skipped.
- **Bounded:** page, item, and byte limits from `bounds.*` apply to every listing; hitting one
  records `truncated` coverage. Listings are paginated.
- **TLS:** verified by default. A verification failure stops collection (the RFC 9728 check is
  skipped as a failed prerequisite); `--insecure` is the only override and is recorded.

## Checks

| Check ID | Operation | Outcomes recorded |
|---|---|---|
| `mcp_initialize` | `initialize` | `success`, `denied` (401/403), `failed` |
| `mcp_tools_list` | `tools/list` | `success`, `skipped` (capability not advertised), `unsupported` (-32601), `denied`, `failed` |
| `mcp_resources_list` | `resources/list` (+ templates) | same as above |
| `mcp_prompts_list` | `prompts/list` | same as above |
| `mcp_rfc9728_metadata` | `rfc9728_protected_resource` | `success`, `failed`, `skipped` |

## Graph output

- **`MCPServer`** (with the `AIService` label): the shared property contract
  (endpoint, access, TLS), `product`/`vendor` and `software_version_raw` (the reported
  implementation), `protocol_version` (kept separate from the implementation version),
  `capabilities`, and `exec_surface = [tool_invocation]` (`declared`) when a tools capability is
  advertised. Every successful check is anonymous, since no credentials are ever sent.
- **`MCPTool`**, **`MCPResource`**, **`MCPPrompt`** with bounded descriptions and schemas. These
  strings come from the scanned server and are **untrusted input**, including to any LLM
  tooling downstream of the graph.
- **Edges:** `ProvidesTool`, `ProvidesResource`, `ProvidesPrompt` (server to child), and
  `ObservedAt` to the existing native node the asset mapping names, or to a fallback
  `NetworkEndpoint`. All non-traversable.
- **Evidence sidecar:** per-check results, a fingerprint record (product, version, protocol
  version), TLS and redirect records, and the correlation decision.

## Not yet implemented

`capability_hint` on tools and content-tier reads of resource
bodies are specified in the [graph model](../02-graph-model.md#property-contract) and scheduled
in the [roadmap](../06-roadmap.md) (D1, D3).
