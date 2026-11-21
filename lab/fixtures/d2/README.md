# D2 fixtures

`fake_ollama.py PORT` is a minimal stand-in for an Ollama server (version, tags, ps) so the real
`llmhound` binary can be run end to end in the lab. It binds loopback only and is started and
stopped by `scripts/run-d2-checks.sh`.
