# Documentation

Read in order. Every document has one job and one canonical home for the rules it states;
others link rather than restate.

## Start here (numbered, in reading order)

| # | Document | Read it to learn | Audience |
|---|---|---|---|
| 0 | [Executive summary](00-executive-summary.md) | What this is, why it matters, status, risks, decisions needed | Everyone, five minutes |
| 1 | [Design](01-design.md) | Architecture, scope, pipeline, scanning behavior, repo layout | Engineers, reviewers |
| 2 | [Graph model](02-graph-model.md) | Node/edge kinds, identity, attachment, property contract, content and secrets, path qualification, implementation status | Engineers, query authors |
| 3 | [Collector capabilities](03-collector-capabilities.md) | Per-surface allowlisted checks and the check-outcome contract | Collector authors |
| 4 | [Saved queries](04-saved-queries.md) | The tier-0 pathing questions as Cypher | Analysts, query authors |
| 5 | [CE compatibility](05-ce-compatibility.md) | Measured BloodHound CE 9.7.1 behavior and open questions | Engineers, upgraders |
| 6 | [Roadmap](06-roadmap.md) | Milestones, status, ordered backlog with exit criteria | Everyone |
| 7 | [Decision log](07-decisions.md) | Why it is shaped this way | Anyone proposing a change |

## Reference (by task)

| Folder | Contents |
|---|---|
| [`guides/`](guides/) | [Configuration](guides/configuration.md) (flags, YAML, mapping file) and the [development guide](guides/development.md) (build, test, lab, CI) |
| [`collectors/`](collectors/README.md) | One page per implemented collector |
| [`internals/`](internals/) | [Checkpoint journal](internals/checkpoint-journal.md) and [scan coverage](internals/scan-coverage.md) |
| [Future ideas](future-ideas.md) | Parked, explicitly out of scope |
| [`../legacy/`](../legacy/README.md) | Retired docs and code, kept for history |

## Who should read what

- **Executive or program owner:** 0, then 6.
- **Operator running a scan:** [README](../README.md), [configuration](guides/configuration.md), then 3.
- **Analyst writing queries:** 2, 4, then 5.
- **Engineer adding a collector:** 1, 2, 3, then [AGENTS.md](../AGENTS.md).
- **AI agent:** [AGENTS.md](../AGENTS.md) first; it points back here by task.

## Keeping these docs true

`go test ./docs` fails if a relative link or anchor breaks, a numbered document is missing
from this index, or a conflict marker is left behind. Run it before every docs change.
