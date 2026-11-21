# Attack-path scenario (SharpHound v6)

Synthetic data for the R checks (`lab/scripts/run-r-checks.sh`). One path to tier 0, built only
from edge kinds CE marks traversable:

```
Domain Users ─GenericAll→ LAB-WIN-01 ─HasSession→ M0-ADM ─MemberOf→ Domain Admins (tier 0)
```

- `LOWPRIV@LAB.LOCAL` is a Domain Users member with no other rights (the "low-privilege start").
- `LAB-WIN-01` is where the AI service attaches (two hops from tier 0).
- `LAB-WIN-02` is a member of Domain Users, so it reaches LAB-WIN-01 through the same `GenericAll`; it has no other edges.

Why a DACL edge and not `AdminTo`: CE 9.7.1 turns SharpHound `LocalGroups` data into the
structural `MemberOfLocalGroup`/`LocalToComputer` edges, which are *not* traversable, and did not
derive `AdminTo` from this synthetic data. See docs/05-ce-compatibility.md (R2).
