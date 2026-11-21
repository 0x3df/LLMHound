# LLMHound — Executive summary

**Reading order:** 1 of 8 (see [docs index](README.md)) · **Audience:** anyone who needs the
whole picture in five minutes · **Status as of 2026-11-21:** core engine, three collectors,
shared property contract (D1), headline saved queries (D2), and bounded content tier (D3)
built and tested; not yet used against a real environment.

## The one-minute version

Our attack-path program answers one question: **"from this asset, what is the shortest
path to tier 0?"** (tier 0 = the accounts and systems whose compromise means losing the
domain). It is built from SharpHound and AzureHound data in BloodHound, and it is blind to
a fast-growing class of infrastructure: **AI services**. Teams are standing up model
servers, agent gateways, notebooks, and vector databases on ordinary corporate hosts, and
some are reachable with no login at all. None of that appears in the graph today.

**LLMHound is a scanner that finds those services and attaches them to the hosts the graph
already knows about.** It runs from one scanner VM, only reads, never logs in, and writes
files that load into BloodHound. Afterwards the same graph can answer: *which hosts that
sit on a path to tier 0 are also running AI services, and which of those are open to
anyone?*

## Why it matters

- AI tooling is routinely deployed fast and unauthenticated. A notebook server or agent
  tool endpoint with no login is often equivalent to remote code execution on its host.
- Those hosts may already be one or two steps from tier 0. Without LLMHound we cannot see
  that; with it, the existing path analysis lights up.
- It adds *context* to an analysis we already trust rather than creating a second,
  competing inventory.

## What it does, end to end

```
 Normalizer's asset list ─┐
 Target ranges ───────────┼─► LLMHound scan ─► files ─► BloodHound ─► shortest-path
 (your authorized scope)  ┘   (read-only,                 (existing       questions,
                               anonymous)                  AD/Azure data)  now AI-aware
```

1. **Scope in.** An operator supplies the network ranges they are authorized to scan, plus
   an asset mapping from the separate normalization program (target → the host's existing
   BloodHound identity). LLMHound does not guess which machine is which; that is the
   normalizer's job.
2. **Find and read.** It probes for known AI services and records only what a service
   volunteers to an anonymous visitor: product and version, whether it demands a login,
   what models, tools, or notebooks it lists, and what it connects to.
3. **Attach.** Each finding links to the host already in BloodHound. Anything it cannot
   attribute is kept as an "unattributed" endpoint for the normalizer to resolve later.
4. **Hand off.** It writes a graph file and an evidence file. Loading them into BloodHound
   is today a manual or pipeline step; a built-in uploader is planned.

## What you can ask afterwards

1. Are there hosts running AI services on an attack path?
2. What is the shortest path from a given asset to an AI host?
3. Which AI hosts are within one or two steps of tier 0?
4. Which AI hosts are open to anyone *and* expose a way to run code?
5. Which AI hosts can ordinary or low-privilege users reach?
6. Which AI gateways or UIs depend on back-ends on other hosts?
7. Which AI services are not yet attributed to a known asset?

## What it deliberately does not do

- **It never logs in, guesses passwords, or tries default credentials**, and it never uses
  a credential it happens to find.
- **It never changes anything or runs anything** on a scanned service: no tool calls, no
  prompts, no job submissions.
- **It never stores a secret.** If a service exposes one, LLMHound records only *that* a
  secret is present, not its value.
- **It does not assert attack paths by default.** What it adds to BloodHound is context;
  the paths still come from the AD and Azure data. A narrow, opt-in set of
  attack-transition rules is planned, each held to a documented evidence bar.
- **It prefers a miss to a false alarm.** In an environment this large, a wrong finding
  costs more than a missing one, so every positive claim needs deterministic evidence.

## Where it stands

| | |
|---|---|
| **Built and tested** | The core engine; end-to-end collection for **3 of the 10 planned core services** (Jupyter, MCP servers, Ollama); shared service properties (D1); default-on, bounded content collection into restricted `.content.jsonl` (D3); high-precision `private_key`, `github_token`, and `aws_access_key` secret detection (D4); a crash-safe scan journal (the resume command itself is planned); graph and evidence output; shipped saved queries (`P1`, `P2`, `P4`, `P6`) validated against **BloodHound CE 9.7.1** in a reproducible lab (D2). |
| **Not built yet** | The other 7 core services (M2b) and long tail (M2c); the planned attack-transition rules (M2d); the built-in uploader and `resume` command (M3). |
| **Not yet done** | A scan of a real environment. Nothing here has run against production. |

The [roadmap](06-roadmap.md) sequences the remaining work; it deliberately gives order and
exit criteria rather than dates.

## Risks and how they are handled

| Risk | Handling |
|---|---|
| Scanning something we are not authorized to scan | Operator-defined scope and exclusions; a `plan` command shows exactly what a scan would touch before any traffic is sent; scans identify themselves with a contact-bearing User-Agent. |
| Collecting sensitive content | Read-only and bounded; content goes to a separate restricted file, never into BloodHound; secrets are flagged as a yes/no and never stored. |
| False positives eroding trust | Precision-first rule for every claim; secret detection only fires on structurally verifiable formats, each proven against a corpus of look-alikes. |
| BloodHound version drift | Support is declared per exact BloodHound CE version, re-validated by a repeatable test suite before any upgrade. |
| Dependence on the normalizer's asset list | Unmapped targets are never guessed; they surface in a dedicated "unattributed" view. |

## Decisions we need from leadership

1. **Authorization.** Who approves the scan scope (ranges and exclusions), and how is
   that approval recorded?
2. **Content collection.** The design collects prompts, configuration, and file bodies by
   default into a restricted file (secrets never stored). Confirm that default, the
   retention period, and who may read that file.
3. **Attack-transition rules.** Do we want the opt-in rules that mark specific
   unauthenticated services (for example, a notebook server with no login) as a way to
   execute code on the host? They would change attack-path results, so they need an owner.
4. **Normalizer contract.** Who owns the asset mapping format and its refresh cadence?
5. **BloodHound version policy.** Which CE version do we pin, and who approves upgrades?

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
