// Package vllm provides anonymous, read-only metadata enumeration of vLLM
// inference servers (/version, /v1/models) without invoking completions or
// mistaking generic OpenAI-compatible servers for vLLM.
package vllm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/0x3df/LLMHound/internal/checkpoint"
	"github.com/0x3df/LLMHound/internal/collectors/internal/common"
	"github.com/0x3df/LLMHound/internal/config"
	"github.com/0x3df/LLMHound/internal/correlate"
	"github.com/0x3df/LLMHound/internal/emitter"
	"github.com/0x3df/LLMHound/internal/evidence"
	"github.com/0x3df/LLMHound/internal/graph"
	"github.com/0x3df/LLMHound/internal/transport"
)

const (
	// Surface is the canonical surface identifier for vLLM.
	Surface = "vllm"

	// DefaultPort is the default listener port for vLLM OpenAI-compatible servers.
	DefaultPort = 8000

	// Allowlisted check identifiers.
	CheckVersion = "vllm_version"
	CheckModels  = "vllm_models"
)

type versionResponse struct {
	Version string `json:"version"`
}

type modelInfo struct {
	ID          string `json:"id"`
	Object      string `json:"object,omitempty"`
	Created     int64  `json:"created,omitempty"`
	OwnedBy     string `json:"owned_by,omitempty"`
	Root        string `json:"root,omitempty"`
	Parent      string `json:"parent,omitempty"`
	MaxModelLen *int64 `json:"max_model_len,omitempty"`
}

type modelsResponse struct {
	Object string      `json:"object"`
	Data   []modelInfo `json:"data"`
}

// Collector implements anonymous, read-only vLLM enumeration.
type Collector struct {
	cfg       config.Config
	transport *transport.Client
}

// Option configures a vLLM Collector.
type Option func(*Collector)

// WithTransport overrides the transport client (primarily for testing).
func WithTransport(tc *transport.Client) Option {
	return func(c *Collector) {
		c.transport = tc
	}
}

// New constructs a vLLM collector with the given configuration.
func New(cfg config.Config, opts ...Option) *Collector {
	c := &Collector{
		cfg:       cfg,
		transport: common.NewTransportClient(cfg),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Collect performs allowlisted GET metadata checks on a vLLM target.
func (c *Collector) Collect(
	ctx context.Context,
	target, scope, vantageKey, scanID string,
	obsTime time.Time,
	resolver *correlate.Resolver,
) (checkpoint.Result, error) {
	if strings.TrimSpace(scope) == "" || strings.TrimSpace(vantageKey) == "" {
		return checkpoint.Result{}, errors.New("collection requires a deployment scope and vantage key")
	}
	if strings.TrimSpace(scanID) == "" {
		return checkpoint.Result{}, errors.New("collection requires a scan ID")
	}
	if obsTime.IsZero() {
		obsTime = time.Now().UTC()
	} else {
		obsTime = obsTime.UTC()
	}

	ep, targetHost, err := common.ParseTargetEndpoint(target, DefaultPort)
	if err != nil {
		return checkpoint.Result{}, err
	}

	srvID, err := graph.NewServiceIdentity(scope, graph.VLLMInstance, ep)
	if err != nil {
		return checkpoint.Result{}, fmt.Errorf("create service identity: %w", err)
	}

	evID := common.EvidenceID(scanID, srvID.ID(), obsTime)
	baseURL := strings.TrimSuffix(ep.String(), "/")
	sourceURL := baseURL + "/v1/models"

	var tlsInfo *transport.TLSInfo
	var redirects []transport.RedirectInfo
	var checks []common.CheckEntry

	var rawVersion string
	var normVersion string
	var verSuccess bool
	var verDenied bool
	var verErr error
	var serverVLLM bool

	var models []modelInfo
	var modelsSuccess bool
	var modelsDenied bool
	var modelsErr error
	var modelsTruncated bool
	var responseTruncated bool

	// 1. Check: GET /version (metadata only; never counts as anon_operations).
	{
		resp, reqErr := c.transport.Get(ctx, baseURL+"/version")
		common.AbsorbTransport(resp, &tlsInfo, &redirects)

		if common.IsTLSFailure(tlsInfo, c.cfg.Insecure) {
			reason := common.SanitizeError(reqErr)
			if reason == "" {
				reason = "TLS certificate verification failed: " + common.BoundString(tlsInfo.VerificationReason, 200)
			}
			checks = append(checks,
				common.CheckEntry{
					CheckID: CheckVersion, Operation: CheckVersion, Outcome: graph.OutcomeFailed,
					Reason: reason, OperationKind: graph.EnumerationOperation,
					Details: map[string]any{"tls_error": common.BoundString(tlsInfo.VerificationReason, 200)},
				},
				common.CheckEntry{
					CheckID: CheckModels, Operation: CheckModels, Outcome: graph.OutcomeSkipped,
					Reason: "prerequisite failed: TLS verification failed", OperationKind: graph.EnumerationOperation,
				},
			)
			return c.buildFailedResult(target, scope, vantageKey, scanID, obsTime, evID, baseURL+"/version", srvID, reason, checks, tlsInfo, redirects)
		}

		if reqErr != nil {
			verErr = reqErr
			reason := common.SanitizeError(reqErr)
			checks = append(checks, common.CheckEntry{
				CheckID: CheckVersion, Operation: CheckVersion, Outcome: graph.OutcomeFailed,
				Reason: reason, OperationKind: graph.EnumerationOperation,
				Details: map[string]any{"error": reason},
			})
		} else {
			if strings.Contains(strings.ToLower(resp.Header.Get("Server")), "vllm") {
				serverVLLM = true
			}
			switch resp.StatusCode {
			case http.StatusOK:
				if resp.Truncated {
					responseTruncated = true
					checks = append(checks, common.CheckEntry{
						CheckID: CheckVersion, Operation: CheckVersion, Outcome: graph.OutcomeFailed,
						Reason: "version response truncated at max_response_bytes limit", OperationKind: graph.EnumerationOperation,
						Details: map[string]any{"http_status": resp.StatusCode, "truncated": true},
					})
				} else {
					var v versionResponse
					if err := json.Unmarshal(resp.Body, &v); err != nil || strings.TrimSpace(v.Version) == "" {
						checks = append(checks, common.CheckEntry{
							CheckID: CheckVersion, Operation: CheckVersion, Outcome: graph.OutcomeFailed,
							Reason: "invalid JSON or missing version in /version response", OperationKind: graph.EnumerationOperation,
							Details: map[string]any{"http_status": resp.StatusCode},
						})
					} else {
						rawVersion = common.BoundString(v.Version, 128)
						normVersion = common.NormalizeVersion(v.Version)
						verSuccess = true
						checks = append(checks, common.CheckEntry{
							CheckID: CheckVersion, Operation: CheckVersion, Outcome: graph.OutcomeSuccess,
							Reason: fmt.Sprintf("vLLM version reported: %s", rawVersion), Anonymous: true,
							OperationKind: graph.EnumerationOperation, CountForAccess: false,
							Details: map[string]any{
								"http_status":          resp.StatusCode,
								"software_version":     normVersion,
								"software_version_raw": rawVersion,
							},
						})
					}
				}
			case http.StatusUnauthorized, http.StatusForbidden:
				verDenied = true
				checks = append(checks, common.CheckEntry{
					CheckID: CheckVersion, Operation: CheckVersion, Outcome: graph.OutcomeDenied,
					Reason:        fmt.Sprintf("HTTP %d: authentication or authorization required", resp.StatusCode),
					OperationKind: graph.EnumerationOperation,
					Details:       map[string]any{"http_status": resp.StatusCode},
				})
			case http.StatusNotFound:
				checks = append(checks, common.CheckEntry{
					CheckID: CheckVersion, Operation: CheckVersion, Outcome: graph.OutcomeFailed,
					Reason: "HTTP 404 not found (version endpoint unavailable)", OperationKind: graph.EnumerationOperation,
					Details: map[string]any{"http_status": resp.StatusCode},
				})
			case http.StatusTooManyRequests:
				checks = append(checks, common.CheckEntry{
					CheckID: CheckVersion, Operation: CheckVersion, Outcome: graph.OutcomeFailed,
					Reason: "HTTP 429 rate limited", OperationKind: graph.EnumerationOperation,
					Details: map[string]any{"http_status": resp.StatusCode},
				})
			default:
				checks = append(checks, common.CheckEntry{
					CheckID: CheckVersion, Operation: CheckVersion, Outcome: graph.OutcomeFailed,
					Reason:        fmt.Sprintf("HTTP %d unexpected status", resp.StatusCode),
					OperationKind: graph.EnumerationOperation,
					Details:       map[string]any{"http_status": resp.StatusCode},
				})
			}
		}
	}

	// 2. Check: GET /v1/models (enumeration check).
	{
		resp, reqErr := c.transport.Get(ctx, baseURL+"/v1/models")
		common.AbsorbTransport(resp, &tlsInfo, &redirects)

		if common.IsTLSFailure(tlsInfo, c.cfg.Insecure) {
			reason := common.SanitizeError(reqErr)
			if reason == "" {
				reason = "TLS certificate verification failed: " + common.BoundString(tlsInfo.VerificationReason, 200)
			}
			checks = append(checks, common.CheckEntry{
				CheckID: CheckModels, Operation: CheckModels, Outcome: graph.OutcomeFailed,
				Reason: reason, OperationKind: graph.EnumerationOperation,
				Details: map[string]any{"tls_error": common.BoundString(tlsInfo.VerificationReason, 200)},
			})
			return c.buildFailedResult(target, scope, vantageKey, scanID, obsTime, evID, sourceURL, srvID, reason, checks, tlsInfo, redirects)
		}

		if reqErr != nil {
			modelsErr = reqErr
			reason := common.SanitizeError(reqErr)
			checks = append(checks, common.CheckEntry{
				CheckID: CheckModels, Operation: CheckModels, Outcome: graph.OutcomeFailed,
				Reason: reason, OperationKind: graph.EnumerationOperation,
				Details: map[string]any{"error": reason},
			})
		} else {
			if strings.Contains(strings.ToLower(resp.Header.Get("Server")), "vllm") {
				serverVLLM = true
			}
			switch resp.StatusCode {
			case http.StatusOK:
				var mResp modelsResponse
				if resp.Truncated {
					responseTruncated = true
					checks = append(checks, common.CheckEntry{
						CheckID: CheckModels, Operation: CheckModels, Outcome: graph.OutcomeFailed,
						Reason: "models response truncated at max_response_bytes limit", OperationKind: graph.EnumerationOperation,
						Details: map[string]any{"http_status": resp.StatusCode, "truncated": true},
					})
				} else if err := json.Unmarshal(resp.Body, &mResp); err != nil || mResp.Data == nil {
					checks = append(checks, common.CheckEntry{
						CheckID: CheckModels, Operation: CheckModels, Outcome: graph.OutcomeFailed,
						Reason: "invalid JSON response from /v1/models", OperationKind: graph.EnumerationOperation,
						Details: map[string]any{"http_status": resp.StatusCode},
					})
				} else if !hasVLLMIdentity(verSuccess, serverVLLM, mResp.Data) {
					checks = append(checks, common.CheckEntry{
						CheckID: CheckModels, Operation: CheckModels, Outcome: graph.OutcomeFailed,
						Reason: "OpenAI-compatible /v1/models response lacks vLLM-specific identity evidence", OperationKind: graph.EnumerationOperation,
						Details: map[string]any{"http_status": resp.StatusCode, "model_count": len(mResp.Data)},
					})
				} else {
					deduped := dedupeModels(mResp.Data)
					maxItems := c.cfg.Bounds.MaxItems
					if maxItems <= 0 {
						maxItems = 10000
					}
					if len(deduped) > maxItems {
						modelsTruncated = true
						models = deduped[:maxItems]
					} else {
						models = deduped
					}
					modelsSuccess = true
					checks = append(checks, common.CheckEntry{
						CheckID: CheckModels, Operation: CheckModels, Outcome: graph.OutcomeSuccess,
						Reason: "served models enumerated anonymously", Anonymous: true,
						OperationKind: graph.EnumerationOperation, CountForAccess: true,
						Details: map[string]any{
							"http_status": resp.StatusCode,
							"model_count": len(models),
							"truncated":   modelsTruncated,
						},
					})
				}
			case http.StatusUnauthorized, http.StatusForbidden:
				modelsDenied = true
				checks = append(checks, common.CheckEntry{
					CheckID: CheckModels, Operation: CheckModels, Outcome: graph.OutcomeDenied,
					Reason:        fmt.Sprintf("HTTP %d: authentication or authorization required", resp.StatusCode),
					OperationKind: graph.EnumerationOperation,
					Details:       map[string]any{"http_status": resp.StatusCode},
				})
			case http.StatusNotFound:
				checks = append(checks, common.CheckEntry{
					CheckID: CheckModels, Operation: CheckModels, Outcome: graph.OutcomeFailed,
					Reason: "HTTP 404 not found (/v1/models endpoint unavailable)", OperationKind: graph.EnumerationOperation,
					Details: map[string]any{"http_status": resp.StatusCode},
				})
			case http.StatusTooManyRequests:
				checks = append(checks, common.CheckEntry{
					CheckID: CheckModels, Operation: CheckModels, Outcome: graph.OutcomeFailed,
					Reason: "HTTP 429 rate limited", OperationKind: graph.EnumerationOperation,
					Details: map[string]any{"http_status": resp.StatusCode},
				})
			default:
				checks = append(checks, common.CheckEntry{
					CheckID: CheckModels, Operation: CheckModels, Outcome: graph.OutcomeFailed,
					Reason:        fmt.Sprintf("HTTP %d unexpected status", resp.StatusCode),
					OperationKind: graph.EnumerationOperation,
					Details:       map[string]any{"http_status": resp.StatusCode},
				})
			}
		}
	}

	var finalCoverage graph.Coverage
	var finalCoverageReason string
	var finalStatus checkpoint.TargetStatus

	switch {
	case verErr != nil && modelsErr != nil:
		finalCoverage = graph.CoverageFailed
		finalStatus = checkpoint.TargetStatusFailed
		finalCoverageReason = "target unreachable: " + common.SanitizeError(verErr)
	case verSuccess && modelsSuccess:
		if modelsTruncated || responseTruncated {
			finalCoverage = graph.CoverageTruncated
			finalStatus = checkpoint.TargetStatusPartial
			finalCoverageReason = truncationReason(modelsTruncated, responseTruncated)
		} else {
			finalCoverage = graph.CoverageComplete
			finalStatus = checkpoint.TargetStatusCompleted
		}
	case modelsSuccess && !verSuccess:
		if modelsTruncated || responseTruncated {
			finalCoverage = graph.CoverageTruncated
			finalStatus = checkpoint.TargetStatusPartial
			finalCoverageReason = truncationReason(modelsTruncated, responseTruncated)
		} else {
			finalCoverage = graph.CoveragePartial
			finalStatus = checkpoint.TargetStatusPartial
			finalCoverageReason = "served models enumerated, but runtime version endpoint unavailable or denied"
		}
	case verSuccess && !modelsSuccess:
		if responseTruncated {
			finalCoverage = graph.CoverageTruncated
			finalStatus = checkpoint.TargetStatusPartial
			finalCoverageReason = "models response truncated at max_response_bytes bound"
		} else {
			finalCoverage = graph.CoveragePartial
			finalStatus = checkpoint.TargetStatusPartial
			finalCoverageReason = "runtime version reported, but served model listing unavailable or denied"
		}
	case verDenied && modelsDenied:
		finalCoverage = graph.CoveragePartial
		finalStatus = checkpoint.TargetStatusPartial
		finalCoverageReason = "authentication required: all metadata endpoints denied access"
	case (verDenied || modelsDenied) && serverVLLM:
		finalCoverage = graph.CoveragePartial
		finalStatus = checkpoint.TargetStatusPartial
		finalCoverageReason = "authentication required on vLLM endpoint"
	default:
		finalCoverage = graph.CoverageFailed
		finalStatus = checkpoint.TargetStatusFailed
		finalCoverageReason = "enumeration failed: target not confirmed as vLLM"
	}

	obs := graph.Observation{
		SchemaVersion:    "1",
		ScanID:           scanID,
		CollectorVersion: "0.1.0",
		EvidenceID:       evID,
		Source:           sourceURL,
		Surface:          Surface,
		ObservedAt:       obsTime,
		DeploymentScope:  scope,
		VantageKey:       vantageKey,
		Coverage:         finalCoverage,
		CoverageReason:   finalCoverageReason,
	}
	if err := obs.Validate(scope); err != nil {
		return checkpoint.Result{}, fmt.Errorf("validate observation: %w", err)
	}

	var nodes []emitter.NodeItem
	var edges []graph.Edge
	var fpInput *evidence.FingerprintInput
	var corrRec *evidence.Record

	if finalCoverage != graph.CoverageFailed {
		access := common.SummarizeAccess(srvID.ID(), obs, checks)
		facts := graph.ServiceFacts{
			Endpoint:   ep,
			Name:       fmt.Sprintf("vLLM · %s:%d", ep.Host(), ep.Port()),
			Product:    "vLLM",
			Vendor:     "vLLM",
			VantageKey: vantageKey,
			Access:     access,
			TLS:        common.TLSSummary(tlsInfo),
		}
		if modelsSuccess {
			facts.ModelCount = common.IntPtr(len(models))
		}
		srvProps := facts.Properties()
		if normVersion != "" {
			srvProps["software_version"] = normVersion
		}
		if rawVersion != "" {
			srvProps["software_version_raw"] = rawVersion
		}

		srvNode, err := graph.NewNode(srvID, obs)
		if err != nil {
			return checkpoint.Result{}, fmt.Errorf("create VLLMInstance node: %w", err)
		}
		srvItem, err := emitter.NewNodeItem(srvNode, srvProps)
		if err != nil {
			return checkpoint.Result{}, fmt.Errorf("create VLLMInstance node item: %w", err)
		}
		nodes = append(nodes, srvItem)

		for _, m := range models {
			modelID, err := graph.NewResourceIdentity(scope, graph.AIModel, srvID, m.ID)
			if err != nil {
				continue
			}
			modelNode, err := graph.NewNode(modelID, obs)
			if err != nil {
				continue
			}
			modelProps := map[string]any{
				"name":     m.ID,
				"model_id": m.ID,
			}
			if owned := common.BoundString(m.OwnedBy, 200); owned != "" {
				modelProps["owned_by"] = owned
			}
			if root := common.BoundString(m.Root, 512); root != "" {
				modelProps["root"] = root
			}
			if parent := common.BoundString(m.Parent, 512); parent != "" {
				modelProps["parent"] = parent
			}
			if m.MaxModelLen != nil && *m.MaxModelLen > 0 {
				modelProps["max_model_len"] = *m.MaxModelLen
			}
			if m.Created > 0 {
				modelProps["created"] = m.Created
			}
			modelItem, err := emitter.NewNodeItem(modelNode, modelProps)
			if err != nil {
				continue
			}
			pmEdge, err := graph.NewTopologyEdge(graph.ProvidesModel, srvID.Reference(), modelID.Reference(), obs)
			if err != nil {
				continue
			}
			nodes = append(nodes, modelItem)
			edges = append(edges, pmEdge)
		}

		corrObs := obs
		corrObs.EvidenceID = evID + "-correlation"
		obsEdge, fbItem, cr, err := common.AttachService(scope, targetHost, srvID, obs, corrObs, resolver)
		if err != nil {
			return checkpoint.Result{}, err
		}
		if fbItem != nil {
			nodes = append(nodes, *fbItem)
		}
		edges = append(edges, obsEdge)
		corrRec = &cr

		method := CheckModels
		confidence := "inferred"
		if verSuccess {
			method = CheckVersion
			confidence = "exact"
		} else if serverVLLM {
			confidence = "exact"
		}
		fpInput = &evidence.FingerprintInput{
			TargetID:           srvID.ID(),
			Product:            "vLLM",
			Vendor:             "vLLM",
			SoftwareVersion:    normVersion,
			SoftwareVersionRaw: rawVersion,
			Method:             method,
			Confidence:         confidence,
		}
	}

	evRecords, err := common.BuildEvidenceRecords(srvID.ID(), obs, evID, checks, fpInput, tlsInfo, redirects, corrRec)
	if err != nil {
		return checkpoint.Result{}, err
	}

	res := checkpoint.Result{
		Target:      target,
		Surface:     Surface,
		Observation: obs,
		Status:      finalStatus,
		Nodes:       nodes,
		Edges:       edges,
		Evidence:    evRecords,
		Error:       finalCoverageReason,
		Details:     map[string]any{"endpoint": ep.String()},
	}
	if err := res.Validate(scope); err != nil {
		return checkpoint.Result{}, fmt.Errorf("validate result: %w", err)
	}
	return res, nil
}

func (c *Collector) buildFailedResult(
	target, scope, vantageKey, scanID string,
	obsTime time.Time,
	evID, sourceURL string,
	srvID graph.Identity,
	reason string,
	checks []common.CheckEntry,
	tlsInfo *transport.TLSInfo,
	redirects []transport.RedirectInfo,
) (checkpoint.Result, error) {
	obs := graph.Observation{
		SchemaVersion:    "1",
		ScanID:           scanID,
		CollectorVersion: "0.1.0",
		EvidenceID:       evID,
		Source:           sourceURL,
		Surface:          Surface,
		ObservedAt:       obsTime,
		DeploymentScope:  scope,
		VantageKey:       vantageKey,
		Coverage:         graph.CoverageFailed,
		CoverageReason:   reason,
	}
	evRecords, err := common.BuildEvidenceRecords(srvID.ID(), obs, evID, checks, nil, tlsInfo, redirects, nil)
	if err != nil {
		return checkpoint.Result{}, err
	}
	res := checkpoint.Result{
		Target:      target,
		Surface:     Surface,
		Observation: obs,
		Status:      checkpoint.TargetStatusFailed,
		Evidence:    evRecords,
		Error:       reason,
	}
	if err := res.Validate(scope); err != nil {
		return checkpoint.Result{}, err
	}
	return res, nil
}

func hasVLLMIdentity(verSuccess, serverVLLM bool, models []modelInfo) bool {
	if verSuccess || serverVLLM {
		return true
	}
	for _, m := range models {
		if strings.EqualFold(strings.TrimSpace(m.OwnedBy), "vllm") || m.MaxModelLen != nil {
			return true
		}
	}
	return false
}

func dedupeModels(in []modelInfo) []modelInfo {
	seen := make(map[string]bool, len(in))
	out := make([]modelInfo, 0, len(in))
	for _, m := range in {
		id := strings.TrimSpace(m.ID)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		m.ID = id
		out = append(out, m)
	}
	return out
}

func truncationReason(modelsTruncated, responseTruncated bool) string {
	var parts []string
	if modelsTruncated {
		parts = append(parts, "model listing truncated at max_items bound")
	}
	if responseTruncated {
		parts = append(parts, "response body truncated at max_response_bytes bound")
	}
	return strings.Join(parts, "; ")
}
