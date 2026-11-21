# Collectors

One package per surface under `internal/collectors/`, each accepted under the
[capability matrix](../03-collector-capabilities.md). A collector is anonymous and read-only,
bounded, TLS-aware, and records an outcome and reason for every check separately from its
coverage.

| Surface | Status | Doc | Package |
|---|---|---|---|
| Jupyter | Implemented | [jupyter.md](jupyter.md) | `internal/collectors/jupyter` |
| MCP | Implemented | [mcp.md](mcp.md) | `internal/collectors/mcp` |
| Ollama | Implemented | [ollama.md](ollama.md) | `internal/collectors/ollama` |
| A2A, vLLM, LiteLLM, Qdrant, MLflow, Open WebUI, LangServe | Planned (M2b) | matrix only | |
| OpenAI-compatible, Ray, Langflow, Flowise, ChromaDB | Planned (M2c) | matrix only | |

Adding a collector: follow the checklist in [AGENTS.md](../../AGENTS.md#adding-a-collector) and
add its row to this table and a `docs/collectors/<surface>.md`.
