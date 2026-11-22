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
| A2A | Implemented | [a2a.md](a2a.md) | `internal/collectors/a2a` |
| vLLM | Implemented | [vllm.md](vllm.md) | `internal/collectors/vllm` |
| Qdrant | Implemented | [qdrant.md](qdrant.md) | `internal/collectors/qdrant` |
| LiteLLM | Implemented | [litellm.md](litellm.md) | `internal/collectors/litellm` |
| MLflow | Implemented | [mlflow.md](mlflow.md) | `internal/collectors/mlflow` |
| Open WebUI | Implemented | [open_webui.md](open_webui.md) | `internal/collectors/openwebui` |
| LangServe | Implemented | [langserve.md](langserve.md) | `internal/collectors/langserve` |
| OpenAI-compatible | Implemented | [openai_compatible.md](openai_compatible.md) | `internal/collectors/openaicompat` |
| Ray | Implemented | [ray.md](ray.md) | `internal/collectors/ray` |
| Langflow | Implemented | [langflow.md](langflow.md) | `internal/collectors/langflow` |
| Flowise | Implemented | [flowise.md](flowise.md) | `internal/collectors/flowise` |
| ChromaDB | Implemented | [chromadb.md](chromadb.md) | `internal/collectors/chromadb` |

Adding a collector: follow the checklist in [AGENTS.md](../../AGENTS.md#adding-a-collector) and
add its row to this table and a `docs/collectors/<surface>.md`.
