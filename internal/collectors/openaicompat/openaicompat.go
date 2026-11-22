// Package openaicompat provides anonymous, read-only metadata enumeration of
// generic OpenAI-compatible /v1/models endpoints when no specific product
// (such as vLLM or LiteLLM) is proven. Inference endpoints are never called.
package openaicompat

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
	// Surface is the canonical surface identifier for generic OpenAI-compatible endpoints.
	Surface = "openai_compatible"

	// DefaultPort is the default listener port probed for OpenAI-compatible endpoints.
	DefaultPort = 8000

	// CheckModels is the allowlisted check identifier for /v1/models.
	CheckModels = "openai_compatible_models"
)

type modelInfo struct {
	ID          string `json:"id"`
	Object      string `json:"object,omitempty"`
	Created     int64  `json:"created,omitempty"`
	OwnedBy     string `json:"owned_by,omitempty"`
	MaxModelLen *int64 `json:"max_model_len,omitempty"`
}

type modelsResponse struct {
	Object string      `json:"object"`
	Data   []modelInfo `json:"data"`
}

// Collector implements anonymous, read-only generic OpenAI-compatible enumeration.
type Collector struct {
	cfg       config.Config
	transport *transport.Client
}

// Option configures an OpenAI-compatible Collector.
type Option func(*Collector)

// WithTransport overrides the transport client (primarily for testing).
func WithTransport(tc *transport.Client) Option {
	return func(c *Collector) {
		c.transport = tc
	}
}

// New constructs a generic OpenAI-compatible collector with the given configuration.
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

// Collect performs a single allowlisted GET /v1/models check without invoking
// completions or embeddings and without guessing specific product identities.
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

	srvID, err := graph.NewServiceIdentity(scope, graph.OpenAICompatibleEndpoint, ep)
	if err != nil {
		return checkpoint.Result{}, fmt.Errorf("create service identity: %w", err)
	}

	evID := common.EvidenceID(scanID, srvID.ID(), obsTime)
	baseURL := strings.TrimSuffix(ep.String(), "/")
	sourceURL := baseURL + "/v1/models"

	var tlsInfo *transport.TLSInfo
	var redirects []transport.RedirectInfo
	var checks []common.CheckEntry

	var models []modelInfo
	var modelsSuccess, modelsDenied, modelsTruncated, responseTruncated bool
	var modelsErr error
	var serverHeader, poweredByHeader string

	resp, reqErr := c.transport.Get(ctx, sourceURL)
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
		serverHeader = common.BoundString(resp.Header.Get("Server"), 128)
		poweredByHeader = common.BoundString(resp.Header.Get("X-Powered-By"), 128)

		switch resp.StatusCode {
		case http.StatusOK:
			if resp.Truncated {
				responseTruncated = true
				checks = append(checks, common.CheckEntry{
					CheckID: CheckModels, Operation: CheckModels, Outcome: graph.OutcomeFailed,
					Reason: "models response truncated at max_response_bytes limit", OperationKind: graph.EnumerationOperation,
					Details: map[string]any{"http_status": resp.StatusCode, "truncated": true},
				})
			} else {
				var mResp modelsResponse
				if err := json.Unmarshal(resp.Body, &mResp); err != nil || mResp.Object != "list" || mResp.Data == nil {
					checks = append(checks, common.CheckEntry{
						CheckID: CheckModels, Operation: CheckModels, Outcome: graph.OutcomeFailed,
						Reason: "response is not a valid OpenAI-compatible /v1/models list", OperationKind: graph.EnumerationOperation,
						Details: map[string]any{"http_status": resp.StatusCode},
					})
				} else if provesSpecificProduct(resp.Header, mResp.Data) {
					checks = append(checks, common.CheckEntry{
						CheckID: CheckModels, Operation: CheckModels, Outcome: graph.OutcomeFailed,
						Reason: "response identifies a specific product rather than generic OpenAI-compatible", OperationKind: graph.EnumerationOperation,
						Details: map[string]any{"http_status": resp.StatusCode},
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
					details := map[string]any{
						"http_status": resp.StatusCode,
						"model_count": len(models),
						"truncated":   modelsTruncated,
					}
					if serverHeader != "" {
						details["server_header"] = serverHeader
					}
					if poweredByHeader != "" {
						details["x_powered_by"] = poweredByHeader
					}
					checks = append(checks, common.CheckEntry{
						CheckID: CheckModels, Operation: CheckModels, Outcome: graph.OutcomeSuccess,
						Reason: "OpenAI-compatible models enumerated anonymously", Anonymous: true,
						OperationKind: graph.EnumerationOperation, CountForAccess: true, Details: details,
					})
				}
			}
		case http.StatusUnauthorized, http.StatusForbidden:
			if hasOpenAICompatibleDenial(resp.Header, resp.Body) {
				modelsDenied = true
			}
			checks = append(checks, common.CheckEntry{
				CheckID: CheckModels, Operation: CheckModels, Outcome: graph.OutcomeDenied,
				Reason:        fmt.Sprintf("HTTP %d: authentication or authorization required", resp.StatusCode),
				OperationKind: graph.EnumerationOperation,
				Details:       map[string]any{"http_status": resp.StatusCode},
			})
		case http.StatusNotFound:
			checks = append(checks, common.CheckEntry{
				CheckID: CheckModels, Operation: CheckModels, Outcome: graph.OutcomeFailed,
				Reason: "HTTP 404 not found (/v1/models unavailable)", OperationKind: graph.EnumerationOperation,
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

	var finalCoverage graph.Coverage
	var finalCoverageReason string
	var finalStatus checkpoint.TargetStatus

	switch {
	case modelsErr != nil:
		finalCoverage = graph.CoverageFailed
		finalStatus = checkpoint.TargetStatusFailed
		finalCoverageReason = "target unreachable: " + common.SanitizeError(modelsErr)
	case modelsSuccess:
		if modelsTruncated || responseTruncated {
			finalCoverage = graph.CoverageTruncated
			finalStatus = checkpoint.TargetStatusPartial
			finalCoverageReason = "model listing truncated at configured bound"
		} else {
			finalCoverage = graph.CoverageComplete
			finalStatus = checkpoint.TargetStatusCompleted
		}
	case modelsDenied:
		finalCoverage = graph.CoveragePartial
		finalStatus = checkpoint.TargetStatusPartial
		finalCoverageReason = "authentication required on OpenAI-compatible /v1/models endpoint"
	default:
		finalCoverage = graph.CoverageFailed
		finalStatus = checkpoint.TargetStatusFailed
		finalCoverageReason = "enumeration failed: target not confirmed as generic OpenAI-compatible"
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
			Name:       fmt.Sprintf("OpenAI-compatible · %s:%d", ep.Host(), ep.Port()),
			Product:    "OpenAI-compatible",
			VantageKey: vantageKey,
			Access:     access,
			TLS:        common.TLSSummary(tlsInfo),
		}
		if modelsSuccess {
			facts.ModelCount = common.IntPtr(len(models))
		}
		srvProps := facts.Properties()
		if serverHeader != "" {
			srvProps["server_header"] = serverHeader
		}
		if poweredByHeader != "" {
			srvProps["x_powered_by"] = poweredByHeader
		}

		srvNode, err := graph.NewNode(srvID, obs)
		if err != nil {
			return checkpoint.Result{}, fmt.Errorf("create OpenAICompatibleEndpoint node: %w", err)
		}
		srvItem, err := emitter.NewNodeItem(srvNode, srvProps)
		if err != nil {
			return checkpoint.Result{}, fmt.Errorf("create OpenAICompatibleEndpoint node item: %w", err)
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

		fpInput = &evidence.FingerprintInput{
			TargetID:   srvID.ID(),
			Product:    "OpenAI-compatible",
			Method:     CheckModels,
			Confidence: "inferred",
			Details: map[string]any{
				"server_header": serverHeader,
			},
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

func provesSpecificProduct(h http.Header, models []modelInfo) bool {
	srv := strings.ToLower(h.Get("Server"))
	if strings.Contains(srv, "vllm") || strings.Contains(srv, "litellm") || strings.Contains(srv, "ollama") {
		return true
	}
	for k := range h {
		if strings.HasPrefix(strings.ToLower(k), "x-litellm-") {
			return true
		}
	}
	for _, m := range models {
		if strings.EqualFold(strings.TrimSpace(m.OwnedBy), "vllm") || m.MaxModelLen != nil {
			return true
		}
	}
	return false
}

func hasOpenAICompatibleDenial(h http.Header, body []byte) bool {
	b := strings.ToLower(string(body))
	return strings.Contains(b, "invalid_api_key") ||
		strings.Contains(b, "incorrect api key") ||
		strings.Contains(b, "you didn't provide an api key") ||
		strings.Contains(b, "openai")
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
