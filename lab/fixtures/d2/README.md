# D2 fixtures

`fake_ollama.py PORT [PORT_FILE]` is a minimal stand-in for an Ollama server
(`/api/version`, `/api/tags`, `/api/ps`, `POST /api/show`) so the real `llmhound`
binary can be run end to end in the lab against ephemeral or fixed loopback ports. It
binds loopback only and is started and stopped by `scripts/run-d2-checks.sh` (which
verifies `D2.0`–`D2.10`, including `.content.jsonl` mode `0600` and D1/D3 properties on
`LLMHound_OllamaInstance`).
