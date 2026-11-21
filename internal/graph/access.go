package graph

import "sort"

// Access summarizes anonymous access outcomes observed for one service or
// resource from one vantage. It is derived from operation-level evidence and
// becomes flat node properties; it is never an edge.
type Access struct {
	// Operations holds the unique, sorted check IDs that succeeded anonymously.
	// Only successes appear here. Denied, failed, and unknown outcomes stay in
	// the evidence sidecar.
	Operations []string
	// AuthObserved is "anonymous" (successes only), "denied" (denials only),
	// "mixed" (both), or "unknown" (neither was observed).
	AuthObserved string
}

// SummarizeAccess derives Access from evidence. Only validated anonymous
// successes count as access; a denial is an observed authentication boundary.
// Other outcomes (failed, skipped, unsupported) say nothing about access.
func SummarizeAccess(evidence []AccessEvidence) Access {
	seen := make(map[string]bool)
	denied := false
	for _, e := range evidence {
		switch {
		case e.Anonymous && e.Outcome == OutcomeSuccess:
			seen[e.CheckID] = true
		case e.Outcome == OutcomeDenied:
			denied = true
		}
	}
	ops := make([]string, 0, len(seen))
	for id := range seen {
		ops = append(ops, id)
	}
	sort.Strings(ops)
	a := Access{Operations: ops, AuthObserved: "unknown"}
	switch {
	case len(ops) > 0 && denied:
		a.AuthObserved = "mixed"
	case len(ops) > 0:
		a.AuthObserved = "anonymous"
	case denied:
		a.AuthObserved = "denied"
	}
	return a
}

// Properties returns the flat, CE-compatible node properties for the summary.
// anon_operations is omitted when empty (CE cannot hold a typed empty array
// usefully and an absent value never implies a denial).
func (a Access) Properties() map[string]any {
	p := map[string]any{"auth_observed": a.AuthObserved}
	if len(a.Operations) > 0 {
		p["anon_operations"] = append([]string(nil), a.Operations...)
	}
	return p
}
