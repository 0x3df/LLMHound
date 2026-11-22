package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/0x3df/LLMHound/internal/emitter"
	"github.com/0x3df/LLMHound/internal/evidence"
	"github.com/0x3df/LLMHound/internal/graph"
)

// ResolveIdentityEdges links discovered service nodes to native cloud identity
// nodes (such as BloodHound AZApp) via non-traversable base edges whenever
// public identity references are observed:
//   - exposed_azapp_ids -> LLMHound_ExposesCredentialFor -> AZApp
//   - entra_client_id   -> LLMHound_AuthenticatesVia     -> AZApp
//
// All native-touching edges are sourceless so emitter routes them to the
// linking payload and BloodHound existence pre-flight checks verify the AZApp
// node exists before ingestion.
func ResolveIdentityEdges(
	scope string,
	nodes []emitter.NodeItem,
	obs graph.Observation,
) ([]graph.Edge, []evidence.Record, error) {
	var outEdges []graph.Edge
	var outEvidence []evidence.Record
	seen := make(map[string]bool)

	for _, item := range nodes {
		srvID := item.Node.Identity()
		if !srvID.Kind().IsService() || srvID.Scope() != scope {
			continue
		}
		srvRef := srvID.Reference()
		baseObs := obs
		if itemObs := item.Node.Observation(); itemObs.Surface != "" {
			baseObs.Surface = itemObs.Surface
		}
		if srcEP, _ := item.Properties["endpoint"].(string); srcEP != "" {
			baseObs.Source = srcEP
		}
		if vk, _ := item.Properties["vantage_key"].(string); vk != "" {
			baseObs.VantageKey = vk
		}
		baseObs.Coverage = graph.CoverageComplete
		baseObs.CoverageReason = ""

		// 1. Exposed Entra client secret credentials -> ExposesCredentialFor -> AZApp
		for _, rawAppID := range toStringSlice(item.Properties["exposed_azapp_ids"]) {
			appID := strings.ToUpper(strings.TrimSpace(rawAppID))
			if appID == "" {
				continue
			}
			key := string(graph.ExposesCredentialFor) + "|" + srvID.ID() + "|" + appID
			if seen[key] {
				continue
			}
			targetRef, err := graph.ExistingNodeByID(graph.Kind("AZApp"), appID)
			if err != nil {
				continue
			}
			sum := sha256.Sum256([]byte(key))
			edgeObs := baseObs
			edgeObs.EvidenceID = "ev-cred-" + hex.EncodeToString(sum[:6])

			edge, err := graph.NewExposesCredentialForEdge(srvRef, targetRef, edgeObs)
			if err != nil {
				return nil, nil, err
			}
			evRec, err := evidence.NewAccessEvidenceRecord(graph.AccessEvidence{
				Observation:   edgeObs,
				CheckID:       "identity_exposed_azapp",
				Operation:     "identity_correlation",
				TargetID:      srvID.ID(),
				Outcome:       graph.OutcomeSuccess,
				Reason:        fmt.Sprintf("service exposed credentials for AZApp %s", appID),
				Anonymous:     true,
				OperationKind: graph.EnumerationOperation,
			}, map[string]any{
				"azapp_id": appID,
				"edge":     string(graph.ExposesCredentialFor),
			})
			if err != nil {
				return nil, nil, err
			}
			seen[key] = true
			outEdges = append(outEdges, edge)
			outEvidence = append(outEvidence, evRec)
		}

		// 2. Passive Entra OAuth/OIDC client ID -> AuthenticatesVia -> AZApp
		if rawClientID, _ := item.Properties["entra_client_id"].(string); strings.TrimSpace(rawClientID) != "" {
			appID := strings.ToUpper(strings.TrimSpace(rawClientID))
			key := string(graph.AuthenticatesVia) + "|" + srvID.ID() + "|" + appID
			if !seen[key] {
				targetRef, err := graph.ExistingNodeByID(graph.Kind("AZApp"), appID)
				if err == nil {
					sum := sha256.Sum256([]byte(key))
					edgeObs := baseObs
					edgeObs.EvidenceID = "ev-oidc-" + hex.EncodeToString(sum[:6])

					edge, err := graph.NewAuthenticatesViaEdge(srvRef, targetRef, edgeObs)
					if err != nil {
						return nil, nil, err
					}
					details := map[string]any{
						"azapp_id": appID,
						"edge":     string(graph.AuthenticatesVia),
					}
					if tenantID, _ := item.Properties["entra_tenant_id"].(string); tenantID != "" {
						details["entra_tenant_id"] = tenantID
					}
					evRec, err := evidence.NewAccessEvidenceRecord(graph.AccessEvidence{
						Observation:   edgeObs,
						CheckID:       "identity_entra_sso",
						Operation:     "identity_correlation",
						TargetID:      srvID.ID(),
						Outcome:       graph.OutcomeSuccess,
						Reason:        fmt.Sprintf("service delegates authentication via AZApp %s", appID),
						Anonymous:     true,
						OperationKind: graph.EnumerationOperation,
					}, details)
					if err != nil {
						return nil, nil, err
					}
					seen[key] = true
					outEdges = append(outEdges, edge)
					outEvidence = append(outEvidence, evRec)
				}
			}
		}
	}

	return outEdges, outEvidence, nil
}
