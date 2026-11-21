# LLMHound M0 — BloodHound CE compatibility lab

A pinned, isolated BloodHound CE + PostgreSQL lab that answers the M0
compatibility questions in
[`docs/reference/ce-compatibility.md`](../docs/reference/ce-compatibility.md)
with reproducible checks. The lab binds to loopback only, never touches any
other BloodHound server, and performs no network scanning of real targets.
All fixtures (toy extension schema, toy payloads, synthetic AD data) are
original to this repository.

## Pin

| Component         | Value                                            |
| ----------------- | ------------------------------------------------ |
| BloodHound CE     | `9.7.1` image tag (GitHub release `v9.7.1`)      |
| Graph database    | PostgreSQL 18 (`graph_driver=pg`, app-db)        |
| Docker images     | `specterops/bloodhound:9.7.1`, `postgres:18`     |

Record the observed image digests in `ce-compatibility.md` when you run the
checks (the `E3` check captures them into the results).

## Requirements

- Docker with the Compose plugin, on a machine where port `127.0.0.1:18080`
  is free (override `BHE_PORT` in `lab/.env` to change it)
- `curl`, `jq`, `zip`, `openssl` on the host

## Run the spike

```bash
cd lab
./scripts/lab-up.sh            # start lab (generates untracked .env with a random password)
./scripts/validate-fixtures.sh # offline fixture validation (no lab needed)
./scripts/run-m0-checks.sh     # run all M0 question checks (~25 min; ingest is asynchronous)
./scripts/lab-down.sh          # stop and remove ONLY this lab's resources
```

`run-m0-checks.sh` writes one JSON line per check to
`lab/.runtime/results/m0-checks.jsonl` and a readable log to
`lab/.runtime/results/m0-log.txt`. Every check prints its HTTP evidence
(status codes, response excerpts, Cypher results) so findings can be traced
back to requests.

Check IDs follow the question numbers in `ce-compatibility.md`:
`Q1.*` kind namespacing, `Q2.*` multi-label nodes, `Q3.*` property types,
`Q4.*` non-traversable edges/pathfinding, `Q5.*` source_kind cleanup and the
AD-computer workaround, `Q6.*` property-matched edge endpoints,
`Q7.*` objectid-matched edges to SharpHound Computers, `Q8.*` upsert
behavior, `Q9.*` saved queries, `Q10.*` ZIP/size handling. `E*` records
environment facts (versions, digests, registries).

## Safety properties

- **Loopback only.** BloodHound CE publishes on `127.0.0.1:<port>`;
  PostgreSQL is not published at all.
- **Dedicated Compose project** (`llmhound-m0-lab`) with labeled volumes.
  `lab-down.sh` runs `docker compose down -v` for that project only — it
  removes only containers/networks/volumes this lab created and never prunes
  Docker globally.
- **No credentials in tracked files.** `lab-up.sh` generates
  `lab/.env` (gitignored) with a random password that doubles as the default
  admin secret; tokens and results live in gitignored `lab/.runtime/`.
- **No real network scanning.** The "targets" in payloads are fixed literal
  probe strings (`127.0.0.1`, `10.0.0.1`); no packets are sent to them.
- **No shared infrastructure.** The lab never connects to an existing
  BloodHound server.

## Files

```
lab/
├── docker-compose.yml            # pinned CE 9.7.1 + postgres:18, loopback-only
├── .env.example                  # template; lab-up.sh derives the real .env
├── fixtures/
│   ├── extension/
│   │   ├── llmhound-m0-schema.json      # toy LLMHound extension (spike-only kinds)
│   │   ├── toyspike-schema.json         # second extension for coexistence checks
│   │   ├── toyspike-collide-schema.json # same kind-name string, different extension
│   │   └── negative/                    # schemas expected to be REJECTED
│   ├── payloads/                        # toy payloads per question (Q2..Q10)
│   │   └── negative/                    # payloads expected to be rejected
│   └── ad/ingest/                       # synthetic SharpHound v6 AD data (LAB.LOCAL)
└── scripts/
    ├── lib.sh                  # API helpers (login, cypher, upload jobs, evidence)
    ├── lab-up.sh / lab-down.sh # lifecycle; teardown is project-scoped
    ├── validate-fixtures.sh    # offline structural validation of all fixtures
    └── run-m0-checks.sh        # the repeatable M0 check suite
```

## Notes

- The lab's random password is reused as `bhe_default_admin_password` so the
  default `admin` user is deterministic; login happens through
  `POST /api/v2/login`.
- Ingest is asynchronous: the suite polls upload jobs to a terminal status
  and allows the source-deletion effects to settle (observed ~1 minute).
- If Docker Desktop is not running, `lab-up.sh` fails fast at the pull step.
  Start Docker first.
