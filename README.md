# LLMHound

**Find the AI services on your network and add them to your BloodHound attack paths.**

LLMHound is a scanner for LLM and agentic-AI infrastructure: MCP servers, Ollama, Jupyter,
vector stores, model gateways. It runs from one machine, **only reads, never logs in**, and
attaches what it finds to the hosts you already have in [BloodHound](https://bloodhound.specterops.io/).
That lets the attack-path graph you built from SharpHound and AzureHound answer questions it
could not before:

> *Which hosts on a path to tier 0 are also running AI services, and which of those are open to anyone?*

New here and short on time? Read the **[executive summary](docs/00-executive-summary.md)**.

## Why it exists

AI tooling gets deployed fast and often without authentication. An unauthenticated notebook
server or agent-tool endpoint can be as good as remote code execution on its host, and those
hosts may already sit one or two steps from tier 0. Today that is invisible to the graph.
LLMHound adds the missing context to an analysis you already trust, rather than inventing a
second inventory.

## How it works

```
 asset mapping (from your normalizer) ─┐
                                       ├─► llmhound scan ─► graph + evidence files ─► BloodHound
 targets you are authorized to scan ───┘    (anonymous, read-only)                    (your existing
                                                                                       AD/Azure graph)
```

1. **Discover.** Bounded probes for known AI-service ports, then HTTP fingerprinting to confirm what each is.
2. **Enumerate.** A read-only collector per service records version, whether it demands a login, and what it lists (models, tools, notebooks, back-ends). Every check records an outcome and a reason; unknown stays unknown.
3. **Attach.** Each service links to the existing BloodHound node your asset mapping names (a `Computer`, an Azure VM, ...). Targets the mapping does not cover become a `NetworkEndpoint` for your normalizer to attribute later. LLMHound never guesses which machine an address is.
4. **Emit.** Files you load into BloodHound: a graph payload, a linking payload, an evidence log, and a crash-safe scan journal.

## Status

| | |
|---|---|
| **Works today** | Offline `targets` and `plan`; `scan` for **Jupyter, MCP, and Ollama** with default-on bounded content collection (`.content.jsonl`) and high-precision secret detection for private keys, classic GitHub tokens, and AWS access-key pairs; checkpoint journal; graph and evidence output; shipped saved BloodHound queries (`extension/saved_searches/`); validated against **BloodHound CE 9.7.1** in a reproducible [lab](lab/README.md). |
| **Planned** | The other seven core surfaces (A2A, vLLM, LiteLLM, Qdrant, MLflow, Open WebUI, LangServe) and a long tail; opt-in attack-transition rules (M2d); `upload` and `resume` (M3). |
| **Not yet done** | A scan of a real environment. Treat it as pre-release. |

See the [roadmap](docs/06-roadmap.md) for the ordered plan.

## What it collects

Anonymous, bounded, and read-only. Nothing is invoked, no credentials are sent or guessed, and
secrets are never stored.

| Surface | Status | What v1 records |
|---|---|---|
| **Jupyter** | ✅ | Auth posture, API version, sessions and kernels, workspace listing, bounded text/notebook bodies (into `.content.jsonl`) |
| **MCP** | ✅ | Server identity and protocol version, tools, resources, prompts, advertised auth servers, bounded text resource bodies (into `.content.jsonl`) |
| **Ollama** | ✅ | Runtime version, model catalog with digests, running models, bounded `/api/show` prompts/modelfiles/templates (into `.content.jsonl`) |
| A2A · vLLM · LiteLLM · Qdrant · MLflow · Open WebUI · LangServe | planned | See the [capability matrix](docs/03-collector-capabilities.md) |
| OpenAI-compatible · Ray · Langflow · Flowise · ChromaDB | planned | Same |

## Quick start

Requires Go 1.27+.

```bash
CGO_ENABLED=0 go build -o llmhound ./cmd/llmhound
cp llmhound.example.yaml llmhound.yaml        # set scope, vantage_key, and your targets

./llmhound plan --config llmhound.yaml        # shows targets × checks; sends no traffic
./llmhound scan --config llmhound.yaml \
    --mapping-file assets.json \
    --output-dir ./out --prefix scan1
```

The asset mapping comes from your normalization program: each entry names the existing
BloodHound node (objectid and kind) for a target.

```json
[{"target": "ai1.corp.example", "object_id": "S-1-5-21-…-1103", "kind": "Computer"},
 {"target": "10.1.2.3",         "object_id": "/SUBSCRIPTIONS/…/VIRTUALMACHINES/AI-VM1", "kind": "AZVM"}]
```

`scan` writes, under `./out`:

| File | Contents |
|---|---|
| `scan1-base.json` (or `scan1.json` when nothing was mapped) | The LLMHound subgraph, tagged `source_kind: LLMHound` |
| `scan1-linking.json` | Edges to your existing nodes, deliberately **without** `source_kind` |
| `scan1.evidence.jsonl` | Per-check results, fingerprints, TLS, redirects, attachment decisions |
| `scan1.content.jsonl` | Bounded content bodies (mode `0600`), written lazily when content is collected |
| `scan1.journal.jsonl` | Crash-safe record of the scan |

**Loading into BloodHound today** is manual (`upload` is planned): ingest the base file first,
then the linking file. Order and the missing `source_kind` matter: a payload that declares a
source kind also tags every node it references, and a later source cleanup would then delete
your Computers. The reasoning is in the [decision log](docs/07-decisions.md).

Full flag and config reference: [configuration guide](docs/guides/configuration.md).

## Responsible use

LLMHound actively probes network services. **Run it only against networks and systems you own
or are explicitly authorized to assess.** Use `plan` first, keep an exclusion list, and leave
the default `User-Agent` (which carries your contact) in place so defenders can attribute the
traffic. Scan output can still be sensitive (model catalogs, workspace file names, backend
references): restrict it, set retention, and keep it out of widely readable systems. Tool and
prompt descriptions come from the scanned service and are **untrusted input**, including to any
LLM tooling downstream of the graph.

## Documentation

Start at the **[documentation index](docs/README.md)**; it gives a reading order and a path by
role. Highlights: [executive summary](docs/00-executive-summary.md) ·
[design](docs/01-design.md) · [graph model](docs/02-graph-model.md) ·
[roadmap](docs/06-roadmap.md) · [decision log](docs/07-decisions.md).

## Contributing

Build, test, and workflow are in the [development guide](docs/guides/development.md); the short
version is `go test -race ./...`, which also verifies the docs. AI agents should start with
[AGENTS.md](AGENTS.md).

## Licensing

Apache-2.0 ([LICENSE](LICENSE)). LLMHound is original code written from scratch; reference
projects (AgentHound, ShareHound, OpenHound, Netwrix AIHound) informed its behavior only, and no
code is derived from them. See the [provenance table](docs/01-design.md#provenance-and-licensing-posture).
