package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/0x3df/LLMHound/internal/config"
	"github.com/0x3df/LLMHound/internal/correlate"
	"github.com/0x3df/LLMHound/internal/emitter"
	"github.com/0x3df/LLMHound/internal/evidence"
	"github.com/0x3df/LLMHound/internal/graph"
)

// Evaluate applies enabled path-qualification rules against replayed scan
// artifacts, emitting opt-in CanExecuteOn and CanAssumePrincipal edges only
// when all six criteria in docs/02-graph-model.md are satisfied.
func Evaluate(
	cfg config.PathQualification,
	nodes []emitter.NodeItem,
	edges []graph.Edge,
	evRecords []evidence.Record,
	obs graph.Observation,
) ([]graph.Edge, []evidence.Record, error) {
	return EvaluateWithResolver(cfg, nodes, edges, evRecords, obs, nil)
}

// Options carries scan context that some rules need beyond the graph itself.
type Options struct {
	// Resolver maps declared worker hosts to existing native nodes.
	Resolver *correlate.Resolver
	// InFanoutScope reports whether a declared worker host is one of the scan's
	// own input targets. Nil means no host is in scope, so cluster fan-out
	// fails closed.
	InFanoutScope func(host string) bool
}

// EvaluateWithResolver is EvaluateWithOptions with only a resolver. Cluster
// fan-out never fires through it because no fan-out scope is supplied.
func EvaluateWithResolver(
	cfg config.PathQualification,
	nodes []emitter.NodeItem,
	edges []graph.Edge,
	evRecords []evidence.Record,
	obs graph.Observation,
	resolver *correlate.Resolver,
) ([]graph.Edge, []evidence.Record, error) {
	return EvaluateWithOptions(cfg, nodes, edges, evRecords, obs, Options{Resolver: resolver})
}

// EvaluateWithOptions behaves like Evaluate and, when cfg.ClusterFanout is set,
// also emits edges toward secondary cluster worker hosts a service declares
// (rule FanoutHostProperty). Declared workers are untrusted input (invariant
// 4): each must resolve through the mapping to an existing native node AND be
// within opts.InFanoutScope, and such edges carry confidence "low".
func EvaluateWithOptions(
	cfg config.PathQualification,
	nodes []emitter.NodeItem,
	edges []graph.Edge,
	evRecords []evidence.Record,
	obs graph.Observation,
	opts Options,
) ([]graph.Edge, []evidence.Record, error) {
	resolver := opts.Resolver
	if len(cfg.EnabledRules) == 0 || (len(cfg.AssumedReachPrincipals) == 0 && len(cfg.VantagePrincipals) == 0) {
		return nil, nil, nil
	}

	builtins, err := BuiltinRules()
	if err != nil {
		return nil, nil, err
	}
	byID := make(map[string]Rule, len(builtins))
	for _, r := range builtins {
		byID[r.ID] = r
	}

	var activeRules []Rule
	for _, rawID := range cfg.EnabledRules {
		id := strings.TrimSpace(rawID)
		r, ok := byID[id]
		if !ok {
			return nil, nil, fmt.Errorf("unknown path-qualification rule %q", id)
		}
		activeRules = append(activeRules, r)
	}

	// Criterion 4: index verified native host attachments (ObservedAt -> native).
	// Unmapped services that only fell back to NetworkEndpoint fail closed.
	nativeHostsByService := make(map[string][]graph.Reference)
	for _, e := range edges {
		if e.Kind() != graph.ObservedAt || !e.End().IsNative() {
			continue
		}
		nativeHostsByService[e.Start().ID()] = append(nativeHostsByService[e.Start().ID()], e.End())
	}

	// Criterion 5: index supporting evidence IDs by service+check and by service.
	evIDsByCheck := make(map[string][]string)
	evIDsByService := make(map[string][]string)
	for _, rec := range evRecords {
		if rec.TargetID == "" || rec.EvidenceID == "" {
			continue
		}
		evIDsByService[rec.TargetID] = appendUniqueStr(evIDsByService[rec.TargetID], rec.EvidenceID)
		if rec.Outcome == "" || rec.Outcome == string(graph.OutcomeSuccess) {
			chk := rec.CheckID
			if chk == "" {
				chk, _ = rec.Details["check_id"].(string)
			}
			if chk != "" {
				key := rec.TargetID + "|" + chk
				evIDsByCheck[key] = appendUniqueStr(evIDsByCheck[key], rec.EvidenceID)
			}
		}
	}

	var outEdges []graph.Edge
	var outEvidence []evidence.Record
	seenEdge := make(map[string]bool)

	for _, item := range nodes {
		srvID := item.Node.Identity().ID()
		srvKind := item.Node.Identity().Kind()
		if !srvKind.IsService() {
			continue
		}
		props := item.Properties
		srvSurface := item.Node.Observation().Surface

		for _, rule := range activeRules {
			if rule.Surface != "*" && srvSurface != rule.Surface {
				continue
			}
			if rule.NodeKind != "*" && string(srvKind) != rule.NodeKind {
				continue
			}

			// Criterion 2: bounded product version match (fail closed unless rule explicitly accepts "*").
			swVer, _ := props["software_version"].(string)
			if rule.VersionRange != "*" {
				okVer, verErr := MatchVersion(swVer, rule.VersionRange)
				if verErr != nil {
					return nil, nil, verErr
				}
				if !okVer {
					continue
				}
			}

			// Required service properties (e.g. auth_required=false, auth_advertised="none", has_exposed_secret=true).
			if !matchesRequiredProps(props, rule.RequiredNodeProps) {
				continue
			}

			// Required declared/inferred execution surface capability (if specified).
			if len(rule.RequiredExecSurfacesAny) > 0 && !matchesAnyExecSurface(props, rule.RequiredExecSurfacesAny) {
				continue
			}

			// Criterion 3: required anonymous capability checks.
			matchedOps, matchedEvIDs := matchRequiredChecks(rule, srvID, props, evIDsByCheck, evIDsByService, item.Node.Observation().EvidenceID)
			if len(rule.RequiredChecksAny) > 0 && len(matchedOps) == 0 {
				continue
			}

			edgeObs := item.Node.Observation()
			if edgeObs.DeploymentScope == "" {
				edgeObs = obs
			}
			if vk, _ := props["vantage_key"].(string); vk != "" {
				edgeObs.VantageKey = vk
			}

			startTargets, err := resolveRuleStarts(rule, cfg, props, edgeObs.VantageKey)
			if err != nil {
				return nil, nil, err
			}
			if len(startTargets) == 0 {
				continue
			}

			emitRuleEdge := func(kind graph.EdgeKind, startRef, endRef graph.Reference, reachBasis string) error {
				edgeKey := fmt.Sprintf("%s|%s|%s|%s", kind, startRef.ID(), endRef.ID(), rule.ID)
				if seenEdge[edgeKey] {
					return nil
				}
				seenEdge[edgeKey] = true

				perEdgeObs := edgeObs
				sum := sha256.Sum256([]byte(edgeKey))
				perEdgeObs.EvidenceID = "ev-rule-" + hex.EncodeToString(sum[:8])

				confidence := rule.Confidence
				if reachBasis == "ray_cluster_fanout" || reachBasis == "ray_head_to_worker" {
					// Worker membership is declared by the target, not observed.
					confidence = "low"
				}
				prov := graph.RuleProvenance{
					RuleID:          rule.ID,
					RuleVersion:     rule.Version,
					Basis:           graph.BasisInferred,
					Confidence:      confidence,
					CapabilityClass: rule.CapabilityClass,
					ReachBasis:      reachBasis,
					ExecIdentity:    rule.ExecIdentity,
					ServiceID:       srvID,
					Operations:      matchedOps,
					EvidenceIDs:     matchedEvIDs,
				}

				var edge graph.Edge
				if kind == graph.CanAssumePrincipal {
					edge, err = graph.NewCanAssumePrincipalEdge(startRef, endRef, perEdgeObs, prov)
				} else {
					edge, err = graph.NewCanExecuteOnEdge(startRef, endRef, perEdgeObs, prov)
				}
				if err != nil {
					return err
				}
				outEdges = append(outEdges, edge)

				evRec, err := evidence.NewAccessEvidenceRecord(graph.AccessEvidence{
					Observation:   perEdgeObs,
					CheckID:       "rule_" + rule.ID,
					Operation:     "path_qualification",
					TargetID:      srvID,
					Outcome:       graph.OutcomeSuccess,
					Reason:        fmt.Sprintf("rule %s v%s qualified %s from %s to %s", rule.ID, rule.Version, kind, startRef.ID(), endRef.ID()),
					Anonymous:     true,
					OperationKind: graph.EnumerationOperation,
				}, map[string]any{
					"rule_id":          rule.ID,
					"rule_version":     rule.Version,
					"edge_kind":        string(kind),
					"capability_class": rule.CapabilityClass,
					"reach_basis":      reachBasis,
					"start_id":         startRef.ID(),
					"end_id":           endRef.ID(),
					"operations":       matchedOps,
					"evidence_ids":     matchedEvIDs,
					"software_version": swVer,
					"docs":             rule.Docs,
				})
				if err != nil {
					return err
				}
				outEvidence = append(outEvidence, evRec)
				return nil
			}

			edgeKind := rule.EffectiveEdgeKind()

			// Variant A: Principal-assumption rule (no host ObservedAt required; targets native identity from property).
			if rule.TargetFromProperty != "" {
				targetRefs := resolveNativeTargetsFromProp(props[rule.TargetFromProperty], graph.Kind(rule.TargetKind))
				for _, targetRef := range targetRefs {
					for _, st := range startTargets {
						if err := emitRuleEdge(edgeKind, st.ref, targetRef, st.reachBasis); err != nil {
							return nil, nil, err
						}
					}
				}
				continue
			}

			// Variant B: Host execution rule requires verified native host attachment.
			hostRefs := nativeHostsByService[srvID]
			if len(hostRefs) == 0 {
				continue
			}

			headIDs := make(map[string]bool, len(hostRefs))
			for _, hostRef := range hostRefs {
				headIDs[hostRef.ID()] = true
				for _, st := range startTargets {
					if err := emitRuleEdge(edgeKind, st.ref, hostRef, st.reachBasis); err != nil {
						return nil, nil, err
					}
				}
			}

			// Variant C: Cluster worker fan-out (e.g. Ray worker IPs -> resolved native worker nodes).
			if rule.FanoutHostProperty != "" && cfg.ClusterFanout && resolver != nil && opts.InFanoutScope != nil {
				for _, workerTarget := range stringSliceProp(props[rule.FanoutHostProperty]) {
					if !opts.InFanoutScope(workerTarget) {
						continue
					}
					cr, rErr := resolver.Resolve(item.Node.Identity().Scope(), workerTarget)
					if rErr != nil || !cr.Target().IsNative() {
						continue
					}
					workerRef := cr.Target()
					if headIDs[workerRef.ID()] {
						continue
					}
					for _, st := range startTargets {
						if err := emitRuleEdge(edgeKind, st.ref, workerRef, "ray_cluster_fanout"); err != nil {
							return nil, nil, err
						}
					}
					for _, headRef := range hostRefs {
						if err := emitRuleEdge(edgeKind, headRef, workerRef, "ray_head_to_worker"); err != nil {
							return nil, nil, err
						}
					}
				}
			}
		}
	}

	return outEdges, outEvidence, nil
}

type ruleStart struct {
	ref        graph.Reference
	reachBasis string
}

func resolveRuleStarts(rule Rule, cfg config.PathQualification, props map[string]any, vantageKey string) ([]ruleStart, error) {
	if rule.StartFromProperty != "" {
		refs := resolveNativeTargetsFromProp(props[rule.StartFromProperty], graph.Kind(rule.StartKind))
		out := make([]ruleStart, 0, len(refs))
		for _, r := range refs {
			out = append(out, ruleStart{ref: r, reachBasis: "entra_sso_app"})
		}
		return out, nil
	}

	reachBasis := "scanner_vantage"
	principals := cfg.AssumedReachPrincipals
	if vk := strings.TrimSpace(vantageKey); vk != "" && len(cfg.VantagePrincipals[vk]) > 0 {
		principals = cfg.VantagePrincipals[vk]
		reachBasis = "vantage_scoped_principal"
	}

	out := make([]ruleStart, 0, len(principals))
	for _, p := range principals {
		ref, err := graph.ExistingNodeByID(p.EffectiveKind(), p.ObjectID)
		if err != nil {
			return nil, fmt.Errorf("invalid principal %q (%s): %w", p.ObjectID, p.EffectiveKind(), err)
		}
		out = append(out, ruleStart{ref: ref, reachBasis: reachBasis})
	}
	return out, nil
}

func resolveNativeTargetsFromProp(raw any, targetKind graph.Kind) []graph.Reference {
	var ids []string
	switch v := raw.(type) {
	case string:
		if strings.TrimSpace(v) != "" {
			ids = []string{v}
		}
	default:
		ids = stringSliceProp(v)
	}
	seen := make(map[string]bool, len(ids))
	var refs []graph.Reference
	for _, rawID := range ids {
		id := strings.ToUpper(strings.TrimSpace(rawID))
		if id == "" || seen[id] {
			continue
		}
		ref, err := graph.ExistingNodeByID(targetKind, id)
		if err != nil {
			continue
		}
		seen[id] = true
		refs = append(refs, ref)
	}
	return refs
}

func matchRequiredChecks(
	rule Rule,
	srvID string,
	props map[string]any,
	evIDsByCheck map[string][]string,
	evIDsByService map[string][]string,
	fallbackEvID string,
) (ops []string, evIDs []string) {
	if len(rule.RequiredChecksAny) == 0 {
		if rule.CapabilityClass == CapabilityPrincipalAssumption {
			ops = []string{"content_secret_scan"}
		} else {
			ops = []string{"entra_sso_enumeration"}
		}
		evIDs = append([]string(nil), evIDsByService[srvID]...)
		if len(evIDs) == 0 && fallbackEvID != "" {
			evIDs = []string{fallbackEvID}
		}
		sort.Strings(evIDs)
		return ops, evIDs
	}

	anonOps := stringSliceProp(props["anon_operations"])
	anonSet := make(map[string]bool, len(anonOps))
	for _, op := range anonOps {
		anonSet[op] = true
	}
	for _, reqChk := range rule.RequiredChecksAny {
		if !anonSet[reqChk] {
			continue
		}
		ops = append(ops, reqChk)
		evIDs = append(evIDs, evIDsByCheck[srvID+"|"+reqChk]...)
	}
	sort.Strings(ops)
	sort.Strings(evIDs)
	evIDs = dedupeSorted(evIDs)
	if len(evIDs) == 0 && fallbackEvID != "" {
		evIDs = []string{fallbackEvID}
	}
	return ops, evIDs
}

func matchesAnyExecSurface(props map[string]any, want []string) bool {
	have := stringSliceProp(props["exec_surface"])
	if len(have) == 0 {
		return false
	}
	for _, h := range have {
		for _, w := range want {
			if strings.EqualFold(strings.TrimSpace(h), strings.TrimSpace(w)) {
				return true
			}
		}
	}
	return false
}

func appendUniqueStr(dst []string, s string) []string {
	for _, existing := range dst {
		if existing == s {
			return dst
		}
	}
	return append(dst, s)
}

func dedupeSorted(in []string) []string {
	if len(in) <= 1 {
		return in
	}
	out := in[:1]
	for _, s := range in[1:] {
		if s != out[len(out)-1] {
			out = append(out, s)
		}
	}
	return out
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
