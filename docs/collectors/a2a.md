# A2A collector

> **Status: M2b A2A collector implemented.** Companion to
> [design](../01-design.md),
> [graph model](../02-graph-model.md), and
> [capability matrix](../03-collector-capabilities.md).
> Implemented in `internal/collectors/a2a`.

The A2A collector performs anonymous, bounded, read-only discovery and
enumeration of Agent2Agent (A2A) endpoints from public agent-card metadata
without invoking skills, creating tasks, or following linked URLs.

## Collection Policy and Safety

- **Read-Only & Anonymous:** No credentials are sent. Only HTTP `GET` requests
  to well-known agent-card paths are issued (`/.well-known/agent-card.json`,
  falling back on 404 to legacy `/.well-known/agent.json`).
- **No Skill Invocation or Link Following:** Linked agent URLs, documentation
  URLs, provider URLs, and additional interface URLs are sanitized (stripping
  credentials, query parameters, and fragments) and recorded as declared
  metadata, never requested.
- **Content Tier & Secret Detection:** When `content.enabled` and
  `content.surfaces.a2a` allow (default `true`), the retrieved agent-card JSON
  is bounded and written to `<prefix>.content.jsonl` (mode `0600`) without an
  extra request. High-precision secret detectors scan the card body, replace any
  verified match with `[secret:<type>]`, record `detected_exposures` by type
  and location in `.evidence.jsonl`, and set `has_exposed_secret`,
  `secret_types`, and `secret_last_confirmed` on `A2AAgent`.
- **TLS & Redirects:** TLS verification is enforced by default (failure stops
  collection unless `--insecure` is set, which is recorded); redirects are
  bounded and authorized per hop.

## Allowlisted Operations

| Check ID | Operation | Endpoint | Method | Purpose | Outcome Semantics |
|---|---|---|---|---|---|
| `a2a_agent_card` | `a2a_agent_card` | `/.well-known/agent-card.json` (fallback `/.well-known/agent.json`) | `GET` | Retrieve public agent card, skills, interfaces, and security declarations | `success`: valid A2A agent card JSON; `denied`: HTTP 401/403; `failed`: 404 on both paths, HTTP 429, malformed/non-A2A JSON, truncated response, or transport error |

## Graph and Evidence Mapping

- **Nodes:**
  - `A2AAgent` (with `AIService` umbrella label), carrying the shared
    [service property contract](../02-graph-model.md#property-contract)
    (endpoint, access, `auth_advertised`, `exec_surface = [tool_invocation]`
    with `exec_surface_basis = declared` when skills or interfaces are present,
    sanitized `backend_refs` with `backend_refs_basis = declared`, `skill_count`,
    content summary, TLS), `agent_name`, `description`, `card_path`,
    `software_version`, `software_version_raw`, `protocol_version`,
    `capabilities`, `security_schemes`, `default_input_modes`,
    `default_output_modes`, `provider_url`, and `documentation_url`.
  - `A2ASkill` nodes (bounded by `bounds.max_items`) for each advertised skill,
    carrying `skill_id`, `skill_name`, `description`, `tags`, `input_modes`, and
    `output_modes`.
  - Fallback `NetworkEndpoint` when the asset mapping does not name an existing
    BloodHound node for the target.
- **Edges:**
  - `AdvertisesSkill` (`A2AAgent` → `A2ASkill`).
  - `ObservedAt` (`A2AAgent` → mapped native node in the sourceless linking
    payload, or fallback `NetworkEndpoint`).
- **Evidence sidecar:** `check_result` / access evidence, `fingerprint`
  (preserving agent version separately from `protocol_version`), `tls`,
  `redirect`, and `correlation` records.
