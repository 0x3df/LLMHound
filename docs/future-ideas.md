# Future potential?

**Status: parked ideas, not an approved plan or roadmap.** These topics are
intentionally absent from active v1 planning. No milestone, schema requirement,
implementation commitment, or acceptance criterion follows from this note.
Revisit only through a separate explicit design decision.

This dot-directory keeps the note out of normal documentation navigation; it
is not a security boundary or a guarantee that Git/editor tools hide it.

## Parked topics

- **Change comparisons (`llmhound diff`):** an offline command comparing two
  evidence sidecars and reporting only like-for-like changes (same scope,
  vantage, check policy, bounds, service identity). Removals only from
  successful, complete listings; denied/failed/partial/truncated collection is
  never reported as removal or revocation. v1 already retains the needed data.
- **CVE matching:** join observed products/versions to vulnerability findings
  from Axonius or its underlying sources. This may belong entirely in the
  owner's external mapping platform rather than LLMHound.
- **Exploit checks:** any active vulnerability validation needs separate
  authorization, safety review, scope, and operational controls.
- **Tool invocation:** executing MCP tools or A2A skills is different from
  reading their advertised metadata; it may modify systems or access sensitive
  information even when the description claims otherwise.
- **Inference requests:** generation, embedding, and other model execution can
  incur cost, consume resources, retain submitted data, or trigger backend work.
- **Host-compromise conclusions beyond the qualification rules:** the active
  design already allows narrow, opt-in rules (M2d, see the
  [path-qualification bar](02-graph-model.md#path-qualification-traversable-edges)).
  Anything broader, or any conclusion that needs evidence beyond service
  inventory and anonymous read-only checks, stays parked.

## Context worth retaining if revisited

The external platform could correlate an Ollama endpoint with an Axonius asset,
a vulnerability finding, and an existing BloodHound Computer. Keep a shared CVE
definition separate from a finding on one installation and from a derived attack
transition. A host-level finding does not automatically apply to every instance.

A potential pivot depends on reachability, actual vulnerability impact,
authentication/configuration prerequisites, execution identity, container/host
boundaries, and onward access. A denial-of-service finding is not code execution;
container execution is not automatically host control. FQDN matching, `RunsOn`,
and a shared CVE node must not manufacture traversable paths.

Any derived transition needs supporting evidence, freshness, rule provenance,
and explicit starting/resulting capabilities. The integration deriving it owns
its lifecycle; it must not misattribute conclusions to LLMHound observations or
remove unrelated/native graph data during cleanup.

None of these ideas requires expanding current v1 beyond anonymous, bounded,
read-only inventory and evidence collection.
