package targets

// PrioritizeTargets reorders canonical target hosts into deterministic waves so
// highest-attack-path-value assets are scanned first:
//  1. Targets for which resolveObjectID returns a mapped ObjectID present in
//     priorityObjectIDs (e.g. hosts on or near Tier 0 from BloodHound).
//  2. All other targets for which resolveObjectID returns mapped=true.
//  3. Unmapped targets (omitted if mappedOnly is true).
//
// Relative lexical order within each tier is preserved.
func PrioritizeTargets(targets []string, resolveObjectID func(target string) (string, bool), priorityObjectIDs map[string]bool, mappedOnly bool) []string {
	if len(targets) == 0 {
		return nil
	}
	if resolveObjectID == nil && !mappedOnly {
		return append([]string(nil), targets...)
	}

	var tier1Priority []string
	var tier2Mapped []string
	var tier3Unmapped []string

	for _, t := range targets {
		objID, mapped := "", false
		if resolveObjectID != nil {
			objID, mapped = resolveObjectID(t)
		}
		if mapped {
			if len(priorityObjectIDs) > 0 && priorityObjectIDs[objID] {
				tier1Priority = append(tier1Priority, t)
			} else {
				tier2Mapped = append(tier2Mapped, t)
			}
			continue
		}
		if !mappedOnly {
			tier3Unmapped = append(tier3Unmapped, t)
		}
	}

	out := make([]string, 0, len(tier1Priority)+len(tier2Mapped)+len(tier3Unmapped))
	out = append(out, tier1Priority...)
	out = append(out, tier2Mapped...)
	out = append(out, tier3Unmapped...)
	return out
}
