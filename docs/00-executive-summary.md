# LLMHound — Executive summary

**Reading order:** 1 of 8 (see [docs index](README.md)) · **Audience:** anyone who needs the
whole picture in five minutes · **Status as of 2026-11-21:** all 15 service collectors,
shared property contract, all 15 saved queries, bounded content tier, high-precision secret
detection, opt-in `CanExecuteOn` path-qualification rules, `llmhound resume`, and
`llmhound upload` are built and tested against fixtures and a pinned CE 9.7.1 lab; not yet
run against a live production environment.

## The one-minute version

A BloodHound attack-path analysis answers one question: **"from this asset, what is the
shortest path to tier 0?"** (tier 0 = the accounts and systems whose compromise means losing
the domain). It is built from SharpHound and AzureHound data in BloodHound, and it is blind
to a fast-growing class of infrastructure: **AI services**. Teams stand up model servers,
agent gateways, notebooks, and vector databases on existing hosts, and some are reachable
with no login at all. Without LLMHound, none of that appears in the graph.

**LLMHound is a scanner that finds those services and attaches them to the hosts BloodHound
already knows about.** It runs from a single scanner host, only reads, never logs in, and
writes files (or uploads directly via `llmhound upload`) into BloodHound. Afterwards the
same graph can answer: *which hosts that sit on a path to tier 0 are also running AI
services, and which of those are open to anyone?*

## Why it matters

- AI tooling is routinely deployed fast and unauthenticated. A notebook server or agent
  tool endpoint with no login is often equivalent to remote code execution on its host.
- Those hosts may already be one or two steps from tier 0. Without LLMHound that context stays
  invisible; with it, existing path analysis highlights the exposure.
- It adds *context* to an existing BloodHound graph rather than creating a second,
  competing asset inventory.

## What it does, end to end

```
 Asset mapping (optional) ─┐
 Target ranges ────────────┼─► LLMHound scan ─► files / upload ─► BloodHound ─► shortest-path
 (your authorized scope)   ┘   (read-only,                        (existing       questions,
                                anonymous)                         AD/Azure data)  now AI-aware
```

1. **Scope in.** An operator supplies the authorized target ranges, plus an optional
   asset mapping from an external asset-inventory or normalization pipeline (target → the
   host's existing BloodHound identity). LLMHound never guesses host attribution.
2. **Find and read.** It probes for 15 known AI service surfaces and records only what a
   service volunteers to an anonymous visitor: product and version, whether it demands a
   login, what models, tools, flows, or notebooks it lists, and what backends it references.
3. **Attach.** Each finding links to the host already in BloodHound. Anything unmapped stays
   attached to an "unattributed" `NetworkEndpoint` for external reconciliation.
4. **Hand off.** It writes a graph payload (plus a sourceless linking payload when targets are
   mapped), an evidence file, a restricted content file (`.content.jsonl`, mode `0600`), and
   a crash-safe scan journal (`llmhound resume`). `llmhound upload` validates the CE instance,
   registers the schema, pre-flights link targets, uploads both payloads safely, and imports
   saved queries.

## What you can ask afterwards

1. Are there hosts running AI services on an attack path?
2. What is the shortest path from a given asset to an AI host?
3. Which AI hosts are within one or two steps of tier 0?
4. Which AI hosts are open to anyone *and* expose a way to run code?
5. Which AI hosts can ordinary or low-privilege users reach?
6. Which AI gateways or UIs depend on back-ends on other hosts?
7. Which AI services are not yet attributed to a known asset?

For a visual example of how LLMHound joins into Active Directory, PAM, virtualization, and
cloud graphs, open the standalone [sample cross-collector attack path](assets/attack-path-sample.html)
in a browser.

## What it deliberately does not do

- **It never logs in, guesses passwords, or tries default credentials**, and it never uses
  a credential it happens to find.
- **It never changes anything or runs anything** on a scanned service: no tool calls, no
  prompts, no job submissions.
- **It never stores a secret.** If a service exposes one, LLMHound records only *that* a
  secret is present, not its value.
- **It does not assert attack paths by default.** What it adds to BloodHound is context;
  the paths still come from the AD and Azure data. Narrow, opt-in attack-transition rules
  (`CanExecuteOn`) are disabled by default and held to a strict six-point evidence bar.
- **It prefers a miss to a false alarm.** At enterprise scale, a wrong finding
  costs more than a missing one, so every positive claim needs deterministic evidence.

## Where it stands

| | |
|---|---|
| **Built and tested** | The core engine; end-to-end collection across **all 15 planned services** (Jupyter, MCP, Ollama, A2A, vLLM, Qdrant, LiteLLM, MLflow, Open WebUI, LangServe, Generic OpenAI-compatible, Ray, Langflow, Flowise, and ChromaDB); shared service properties (D1); default-on, bounded content collection into restricted `.content.jsonl` (D3); high-precision `private_key`, `github_token`, and `aws_access_key` secret detection (D4); opt-in `CanExecuteOn` path-qualification rules (D7); crash-safe scan journal and `llmhound resume`, mapping provenance (`mapping_source`), the `llmhound upload` BloodHound CE client with read-only existence pre-flight and adapter validation gate, and all **15 shipped saved queries** (`P1`–`P8`, `I1`–`I7`) against **BloodHound CE 9.7.1** (D2, D8). |
| **Not built yet** | Credentialed enumeration (M4) and per-kind node/edge reference docs (M5). |
| **Not yet done** | A scan of a real environment. Nothing here has run against production. |

The [roadmap](06-roadmap.md) sequences the remaining work; it deliberately gives order and
exit criteria rather than dates.

## Risks and how they are handled

| Risk | Handling |
|---|---|
| Scanning unauthorized targets | Operator-defined scope and exclusions; `llmhound plan` shows exactly what a scan would touch before any traffic is sent; configurable identifiable User-Agent. |
| Collecting sensitive content | Read-only and bounded; content goes to a separate restricted file, never into BloodHound; secrets are flagged as a yes/no and never stored. |
| False positives eroding trust | Precision-first rule for every claim; secret detection only fires on structurally verifiable formats, each proven against a corpus of look-alikes. |
| BloodHound version drift | Support is declared per exact BloodHound CE version and verified by `llmhound upload` before ingest (`v9.7.1` pinned). |
| Missing or stale asset mappings | Unmapped targets are never guessed; they surface in a dedicated "unattributed" view (`NetworkEndpoint`). |

## Operational decisions before first scan

1. **Authorization.** Who approves the scan scope (ranges and exclusions), and how is
   that approval recorded?
2. **Content collection.** The default configuration collects prompts, configuration, and
   file bodies into a restricted `.content.jsonl` file (mode `0600`, secrets never stored).
   Confirm retention, access controls, or whether to disable content collection globally or
   per surface.
3. **Attack-transition rules.** Opt-in `CanExecuteOn` rules mark specific unauthenticated
   services as host code execution edges from configured principals. They ship disabled;
   enable only with explicit owner sign-off and verified asset mappings.
4. **Asset mapping contract.** Which external inventory or normalization pipeline produces
   `mapping_file`, and what is its refresh cadence?
5. **BloodHound version policy.** Match the pinned CE version (`v9.7.1`) or re-run the
   lab suite before upgrading (`--allow-unvalidated-ce`).

## Glossary

- **BloodHound / attack path.** A graph tool that links identities and machines by the
  access relationships between them, so a "path" shows how one foothold leads to another.
- **SharpHound / AzureHound.** The collectors that feed BloodHound from Active Directory
  and Azure.
- **Tier 0.** The most privileged assets, such as domain controllers and domain admins.
- **OpenGraph.** BloodHound's format for adding new kinds of data to the graph.
- **MCP / agent tools.** A protocol that lets AI assistants call tools and read data;
  an exposed MCP server can be a path to whatever its tools can reach.
- **Normalizer.** The separate program that decides which machine an address belongs to
  and cleans stale data; LLMHound relies on it rather than duplicating it.

**Next:** [Design](01-design.md) for how it works · [Roadmap](06-roadmap.md) for what is next
· [Decisions](07-decisions.md) for why it is shaped this way.
