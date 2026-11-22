package bloodhound

import (
	"context"
	"fmt"
	"strings"
)

// Tier0AdjacentObjectIDs queries BloodHound CE read-only for the ObjectIDs of
// Tag_Tier_Zero nodes and hosts/principals within 1..hops traversable edges of
// Tag_Tier_Zero (plus Tag_Owned nodes). Operators use this set with
// PrioritizeTargets / scan --prioritize-from-bh to sweep highest-impact hosts first.
func (c *Client) Tier0AdjacentObjectIDs(ctx context.Context, hops, limit int) (map[string]bool, error) {
	ids, _, err := c.Tier0AdjacentObjectIDsWithCap(ctx, hops, limit)
	return ids, err
}

// CEResultCap is the approximate per-query node cap measured on CE 9.7.1
// (R2(e), R7): larger results are silently truncated near this size.
const CEResultCap = 1000

// Tier0AdjacentObjectIDsWithCap is Tier0AdjacentObjectIDs and also reports
// whether any seed query reached CE's result cap, meaning the priority set is
// a subset. Prioritization only orders targets, so a truncated set never drops
// a target from the scan, but operators should know the ordering is partial.
func (c *Client) Tier0AdjacentObjectIDsWithCap(ctx context.Context, hops, limit int) (map[string]bool, bool, error) {
	if hops <= 0 {
		hops = 2
	}
	if hops > 3 {
		hops = 3
	}
	if limit <= 0 {
		limit = 5000
	}
	if limit > 50000 {
		limit = 50000
	}

	out := make(map[string]bool)
	capped := false
	collect := func(res CypherResult) {
		if len(res.Nodes) >= CEResultCap || len(res.Nodes) >= limit {
			capped = true
		}
		for _, node := range res.Nodes {
			if len(node.Kinds) == 0 {
				continue
			}
			id := strings.ToUpper(strings.TrimSpace(node.ObjectID))
			if id == "" {
				if raw, ok := node.Properties["objectid"].(string); ok {
					id = strings.ToUpper(strings.TrimSpace(raw))
				}
			}
			if id != "" {
				out[id] = true
			}
		}
	}

	// 1. Direct Tier-0 nodes (CE limits single query results near ~1,000 nodes).
	t0Res, err := c.Cypher(ctx, fmt.Sprintf("MATCH (t:Tag_Tier_Zero) RETURN t LIMIT %d", limit), false)
	if err != nil {
		return nil, false, fmt.Errorf("query Tier-0 nodes: %w", err)
	}
	collect(t0Res)

	// 2. Owned nodes (high-priority foothold targets).
	ownedRes, err := c.Cypher(ctx, fmt.Sprintf("MATCH (o:Tag_Owned) RETURN o LIMIT %d", limit), false)
	if err != nil {
		return nil, false, fmt.Errorf("query Owned nodes: %w", err)
	}
	collect(ownedRes)

	// 3. Hosts/nodes within 1..hops traversable edges of Tag_Tier_Zero.
	kinds, err := c.TraversablePathKinds(ctx, false)
	if err != nil {
		return nil, false, fmt.Errorf("query traversable path kinds: %w", err)
	}
	if len(kinds) > 0 {
		pk := strings.Join(kinds, "|")
		adjQuery := fmt.Sprintf("MATCH (n)-[:%s*1..%d]->(:Tag_Tier_Zero) RETURN n LIMIT %d", pk, hops, limit)
		adjRes, err := c.Cypher(ctx, adjQuery, false)
		if err != nil {
			return nil, false, fmt.Errorf("query Tier-0 adjacent nodes: %w", err)
		}
		collect(adjRes)
	}

	return out, capped, nil
}
