package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"sort"

	"github.com/0x3df/LLMHound/internal/config"
	"github.com/0x3df/LLMHound/internal/emitter"
	"github.com/0x3df/LLMHound/internal/evidence"
	"github.com/0x3df/LLMHound/internal/graph"
)

// Evaluate applies enabled path-qualification rules against replayed scan
// artifacts, emitting opt-in CanExecuteOn edges and rule evidence records only
// when all six criteria in docs/02-graph-model.md are satisfied.
func Evaluate(
	cfg config.PathQualification,
	nodes []emitter.NodeItem,
	edges []graph.Edge,
	evRecords []evidence.Record,
	obs graph.Observation,
) ([]graph.Edge, []evidence.Record, error) {
	if len(cfg.EnabledRules) == 0 || len(cfg.AssumedReachPrincipals) == 0 {
		return nil, nil, nil
	}
	allRules, err := BuiltinRules()
	if err != nil {
		return nil, nil, err
	}
	ruleByID := make(map[string]Rule, len(allRules))
	for _, r := range allRules {
		ruleByID[r.ID] = r
	}

	var activeRules []Rule
	for _, id := range cfg.EnabledRules {
		r, ok := ruleByID[id]
		if !ok {
			return nil, nil, fmt.Errorf("unknown path-qualification rule %q", id)
		}
		activeRules = append(activeRules, r)
	}

	var principals []graph.Reference
	for _, p := range cfg.AssumedReachPrincipals {
		ref, err := graph.ExistingNodeByID(p.EffectiveKind(), p.ObjectID)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid assumed_reach_principal %q: %w", p.ObjectID, err)
		}
		principals = append(principals, ref)
	}

	// Criterion 4: index verified native host attachments (ObservedAt -> native).
	// NetworkEndpoint targets are never eligible.
	nativeHostsByService := make(map[string][]graph.Reference)
	seenHostByService := make(map[string]map[string]bool)
	for _, e := range edges {
		if e.Kind() != graph.ObservedAt || !e.End().IsNative() {
			continue
		}
		srvID := e.Start().ID()
		hostID := e.End().ID()
		if seenHostByService[srvID] == nil {
			seenHostByService[srvID] = make(map[string]bool)
		}
		if !seenHostByService[srvID][hostID] {
			seenHostByService[srvID][hostID] = true
			nativeHostsByService[srvID] = append(nativeHostsByService[srvID], e.End())
		}
	}

	// Criterion 2: index positive anonymous check evidence by (TargetID, CheckID).
	type checkKey struct {
		targetID string
		checkID  string
	}
	evIDsByCheck := make(map[checkKey][]string)
	for _, ev := range evRecords {
		if ev.RecordType != evidence.RecordCheckResult {
			continue
		}
		if ev.Outcome != string(graph.OutcomeSuccess) || ev.Anonymous == nil || !*ev.Anonymous {
			continue
		}
		if ev.TargetID == "" || ev.CheckID == "" || ev.EvidenceID == "" {
			continue
		}
		k := checkKey{targetID: ev.TargetID, checkID: ev.CheckID}
		evIDsByCheck[k] = append(evIDsByCheck[k], ev.EvidenceID)
	}

	var outEdges []graph.Edge
	var outEvidence []evidence.Record
	seenEdge := make(map[string]bool)

	for _, item := range nodes {
		id := item.Node.Identity()
		if !id.Kind().IsService() {
			continue
		}
		srvID := id.ID()
		nativeHosts := nativeHostsByService[srvID]
		if len(nativeHosts) == 0 {
			continue
		}

		// Criterion 3: require software_version (never api_version).
		swVer, _ := item.Properties["software_version"].(string)
		if swVer == "" {
			continue
		}
		anonOps := stringSliceProp(item.Properties["anon_operations"])
		if len(anonOps) == 0 {
			continue
		}
		anonSet := make(map[string]bool, len(anonOps))
		for _, op := range anonOps {
			anonSet[op] = true
		}

		for _, rule := range activeRules {
			if string(id.Kind()) != rule.NodeKind {
				continue
			}
			matchedVer, err := MatchVersion(swVer, rule.VersionRange)
			if err != nil || !matchedVer {
				continue
			}
			if !matchesRequiredProps(item.Properties, rule.RequiredNodeProps) {
				continue
			}

			var matchedOps []string
			var matchedEvIDs []string
			evSeen := make(map[string]bool)
			for _, reqChk := range rule.RequiredChecksAny {
				if !anonSet[reqChk] {
					continue
				}
				evIDs := evIDsByCheck[checkKey{targetID: srvID, checkID: reqChk}]
				if len(evIDs) == 0 {
					continue
				}
				matchedOps = append(matchedOps, reqChk)
				for _, eid := range evIDs {
					if !evSeen[eid] {
						evSeen[eid] = true
						matchedEvIDs = append(matchedEvIDs, eid)
					}
				}
			}
			if len(matchedOps) == 0 || len(matchedEvIDs) == 0 {
				continue
			}
			sort.Strings(matchedOps)
			sort.Strings(matchedEvIDs)

			nodeObs := item.Node.Observation()
			ruleObs := obs
			if ruleObs.ScanID == "" {
				ruleObs = nodeObs
			}
			ruleObs.Surface = rule.Surface
			ruleObs.Source = nodeObs.Source
			ruleObs.Coverage = nodeObs.Coverage
			ruleObs.CoverageReason = nodeObs.CoverageReason

			for _, hostRef := range nativeHosts {
				for _, principalRef := range principals {
					edgeKey := rule.ID + "|" + principalRef.ID() + "|" + hostRef.ID()
					if seenEdge[edgeKey] {
						continue
					}
					seenEdge[edgeKey] = true

					sum := sha256.Sum256([]byte(rule.ID + "|" + srvID + "|" + principalRef.ID() + "|" + hostRef.ID()))
					evID := "ev-rule-" + rule.ID + "-" + hex.EncodeToString(sum[:6])
					edgeObs := ruleObs
					edgeObs.EvidenceID = evID

					prov := graph.RuleProvenance{
						RuleID:          rule.ID,
						RuleVersion:     rule.Version,
						Basis:           graph.BasisInferred,
						Confidence:      rule.Confidence,
						CapabilityClass: rule.CapabilityClass,
						ReachBasis:      "scanner_vantage",
						ExecIdentity:    rule.ExecIdentity,
						ServiceID:       srvID,
						Operations:      matchedOps,
						EvidenceIDs:     matchedEvIDs,
					}
					edge, err := graph.NewCanExecuteOnEdge(principalRef, hostRef, edgeObs, prov)
					if err != nil {
						return nil, nil, err
					}
					outEdges = append(outEdges, edge)

					anon := true
					evRec, err := evidence.NewAccessEvidenceRecord(graph.AccessEvidence{
						Observation:   edgeObs,
						CheckID:       "rule_" + rule.ID,
						Operation:     "path_qualification",
						TargetID:      srvID,
						Outcome:       graph.OutcomeSuccess,
						Reason:        fmt.Sprintf("rule %s v%s qualified CanExecuteOn from %s to %s", rule.ID, rule.Version, principalRef.ID(), hostRef.ID()),
						Anonymous:     anon,
						OperationKind: graph.EnumerationOperation,
					}, map[string]any{
						"rule_id":          rule.ID,
						"rule_version":     rule.Version,
						"capability_class": rule.CapabilityClass,
						"start_id":         principalRef.ID(),
						"end_id":           hostRef.ID(),
						"operations":       matchedOps,
						"evidence_ids":     matchedEvIDs,
						"software_version": swVer,
						"docs":             rule.Docs,
					})
					if err != nil {
						return nil, nil, err
					}
					outEvidence = append(outEvidence, evRec)
				}
			}
		}
	}

	return outEdges, outEvidence, nil
}

func stringSliceProp(v any) []string {
	switch s := v.(type) {
	case []string:
		return s
	case []any:
		out := make([]string, 0, len(s))
		for _, item := range s {
			if str, ok := item.(string); ok {
				out = append(out, str)
			}
		}
		return out
	default:
		return nil
	}
}

func matchesRequiredProps(nodeProps, reqProps map[string]any) bool {
	for k, want := range reqProps {
		got, ok := nodeProps[k]
		if !ok {
			return false
		}
		if !reflect.DeepEqual(got, want) {
			return false
		}
	}
	return true
}
