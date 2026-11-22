// Package flowise provides anonymous, read-only metadata enumeration of
// Flowise endpoints (/api/v1/version, /api/v1/chatflows) and bounded flow
// configuration capture without calling prediction endpoints.
package flowise

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
	"github.com/0x3df/LLMHound/internal/content"
	"github.com/0x3df/LLMHound/internal/correlate"
	"github.com/0x3df/LLMHound/internal/emitter"
	"github.com/0x3df/LLMHound/internal/evidence"
	"github.com/0x3df/LLMHound/internal/graph"
	"github.com/0x3df/LLMHound/internal/secrets"
	"github.com/0x3df/LLMHound/internal/transport"
)

const (
	// Surface is the canonical surface identifier for Flowise.
	Surface = "flowise"

	// DefaultPort is the default listener port for Flowise.
	DefaultPort = 3000

	// Allowlisted check identifiers.
	CheckVersion    = "flowise_version"
	CheckChatflows  = "flowise_chatflows"
	CheckFlowConfig = "flowise_flow_config"
)

type versionResponse struct {
	Version     string `json:"version"`
	Package     string `json:"package"`
	MainVersion string `json:"main_version"`
}

type chatflowEntry struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Deployed *bool  `json:"deployed,omitempty"`
	IsPublic *bool  `json:"isPublic,omitempty"`
	Type     string `json:"type,omitempty"`
	FlowData string `json:"flowData,omitempty"`
}

// Collector implements anonymous, read-only Flowise enumeration.
type Collector struct {
	cfg         config.Config
	transport   *transport.Client
	contentSink content.Sink
}

// Option configures a Flowise Collector.
type Option func(*Collector)

// WithTransport overrides the transport client (primarily for testing).
func WithTransport(tc *transport.Client) Option {
	return func(c *Collector) {
		c.transport = tc
	}
}

// WithContentSink configures where bounded chatflow configurations are written.
func WithContentSink(sink content.Sink) Option {
	return func(c *Collector) {
		c.contentSink = sink
	}
}

// New constructs a Flowise collector with the given configuration.
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

// Collect performs allowlisted GET metadata checks and bounded flow config
// capture on a Flowise server without calling prediction endpoints.
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

	srvID, err := graph.NewServiceIdentity(scope, graph.FlowiseInstance, ep)
	if err != nil {
		return checkpoint.Result{}, fmt.Errorf("create service identity: %w", err)
	}

	evID := common.EvidenceID(scanID, srvID.ID(), obsTime)
	baseURL := strings.TrimSuffix(ep.String(), "/")
	sourceURL := baseURL + "/api/v1/chatflows"

	var tlsInfo *transport.TLSInfo
	var redirects []transport.RedirectInfo
	var checks []common.CheckEntry
	var degraded []string

	var flowiseConfirmed bool
	var deniedConfirmed bool
	var langflowRejected bool
	var rawVersion, normVersion string
	var verSuccess, verDenied bool
	var verErr error

	var chatflows []chatflowEntry
	var flowsSuccess, flowsDenied, flowsTruncated bool
	var flowsErr error
	var responseTruncated bool

	maxItems := c.cfg.Bounds.MaxItems
	if maxItems <= 0 {
		maxItems = 10000
	}

	// 1. Check: GET /api/v1/version (metadata only; never counts as anon_operations).
	{
		resp, reqErr := c.transport.Get(ctx, baseURL+"/api/v1/version")
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
				common.CheckEntry{CheckID: CheckChatflows, Operation: CheckChatflows, Outcome: graph.OutcomeSkipped, Reason: "prerequisite failed: TLS verification failed", OperationKind: graph.EnumerationOperation},
				common.CheckEntry{CheckID: CheckFlowConfig, Operation: CheckFlowConfig, Outcome: graph.OutcomeSkipped, Reason: "prerequisite failed: TLS verification failed", OperationKind: graph.ResourceReadOperation},
			)
			return c.buildFailedResult(target, scope, vantageKey, scanID, obsTime, evID, baseURL+"/api/v1/version", srvID, reason, checks, tlsInfo, redirects)
		}

		if reqErr != nil {
			verErr = reqErr
			reason := common.SanitizeError(reqErr)
			degraded = append(degraded, "version check failed: "+reason)
			checks = append(checks, common.CheckEntry{
				CheckID: CheckVersion, Operation: CheckVersion, Outcome: graph.OutcomeFailed,
				Reason: reason, OperationKind: graph.EnumerationOperation,
				Details: map[string]any{"error": reason},
			})
		} else {
			if hasFlowiseHeaders(resp.Header) {
				flowiseConfirmed = true
			}
			switch resp.StatusCode {
			case http.StatusOK:
				if resp.Truncated {
					responseTruncated = true
					degraded = append(degraded, "version response truncated at max_response_bytes")
					checks = append(checks, common.CheckEntry{
						CheckID: CheckVersion, Operation: CheckVersion, Outcome: graph.OutcomeFailed,
						Reason: "version response truncated at max_response_bytes limit", OperationKind: graph.EnumerationOperation,
						Details: map[string]any{"http_status": resp.StatusCode, "truncated": true},
					})
				} else {
					var v versionResponse
					if err := json.Unmarshal(resp.Body, &v); err != nil || strings.TrimSpace(v.Version) == "" {
						degraded = append(degraded, "invalid JSON or missing version in /api/v1/version")
						checks = append(checks, common.CheckEntry{
							CheckID: CheckVersion, Operation: CheckVersion, Outcome: graph.OutcomeFailed,
							Reason: "invalid JSON or missing version in /api/v1/version", OperationKind: graph.EnumerationOperation,
							Details: map[string]any{"http_status": resp.StatusCode},
						})
					} else if strings.Contains(strings.ToLower(v.Package), "langflow") || strings.TrimSpace(v.MainVersion) != "" {
						langflowRejected = true
						degraded = append(degraded, "/api/v1/version identifies Langflow, not Flowise")
						checks = append(checks, common.CheckEntry{
							CheckID: CheckVersion, Operation: CheckVersion, Outcome: graph.OutcomeFailed,
							Reason: "version payload identifies Langflow rather than Flowise", OperationKind: graph.EnumerationOperation,
							Details: map[string]any{"http_status": resp.StatusCode},
						})
					} else {
						verSuccess = true
						rawVersion = common.BoundString(v.Version, 128)
						normVersion = common.NormalizeVersion(v.Version)
						checks = append(checks, common.CheckEntry{
							CheckID: CheckVersion, Operation: CheckVersion, Outcome: graph.OutcomeSuccess,
							Reason: fmt.Sprintf("Flowise version reported: %s", rawVersion), Anonymous: true,
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
				if hasFlowiseDenial(resp.Header, resp.Body) {
					flowiseConfirmed = true
					deniedConfirmed = true
				}
				degraded = append(degraded, fmt.Sprintf("version denied (HTTP %d)", resp.StatusCode))
				checks = append(checks, common.CheckEntry{
					CheckID: CheckVersion, Operation: CheckVersion, Outcome: graph.OutcomeDenied,
					Reason:        fmt.Sprintf("HTTP %d: authentication or authorization required", resp.StatusCode),
					OperationKind: graph.EnumerationOperation,
					Details:       map[string]any{"http_status": resp.StatusCode},
				})
			case http.StatusNotFound:
				degraded = append(degraded, "version endpoint unavailable (HTTP 404)")
				checks = append(checks, common.CheckEntry{
					CheckID: CheckVersion, Operation: CheckVersion, Outcome: graph.OutcomeFailed,
					Reason: "HTTP 404 not found (/api/v1/version unavailable)", OperationKind: graph.EnumerationOperation,
					Details: map[string]any{"http_status": resp.StatusCode},
				})
			default:
				degraded = append(degraded, fmt.Sprintf("version returned HTTP %d", resp.StatusCode))
				checks = append(checks, common.CheckEntry{
					CheckID: CheckVersion, Operation: CheckVersion, Outcome: graph.OutcomeFailed,
					Reason:        fmt.Sprintf("HTTP %d unexpected status", resp.StatusCode),
					OperationKind: graph.EnumerationOperation,
					Details:       map[string]any{"http_status": resp.StatusCode},
				})
			}
		}
	}

	// 2. Check: GET /api/v1/chatflows (enumeration check).
	publicCount := 0
	if langflowRejected {
		checks = append(checks, common.CheckEntry{
			CheckID: CheckChatflows, Operation: CheckChatflows, Outcome: graph.OutcomeSkipped,
			Reason: "prerequisite failed: target identified as Langflow, not Flowise", OperationKind: graph.EnumerationOperation,
		})
	} else {
		resp, reqErr := c.transport.Get(ctx, sourceURL)
		common.AbsorbTransport(resp, &tlsInfo, &redirects)

		if common.IsTLSFailure(tlsInfo, c.cfg.Insecure) {
			reason := common.SanitizeError(reqErr)
			if reason == "" {
				reason = "TLS certificate verification failed: " + common.BoundString(tlsInfo.VerificationReason, 200)
			}
			checks = append(checks,
				common.CheckEntry{
					CheckID: CheckChatflows, Operation: CheckChatflows, Outcome: graph.OutcomeFailed,
					Reason: reason, OperationKind: graph.EnumerationOperation,
					Details: map[string]any{"tls_error": common.BoundString(tlsInfo.VerificationReason, 200)},
				},
				common.CheckEntry{CheckID: CheckFlowConfig, Operation: CheckFlowConfig, Outcome: graph.OutcomeSkipped, Reason: "prerequisite failed: TLS verification failed", OperationKind: graph.ResourceReadOperation},
			)
			return c.buildFailedResult(target, scope, vantageKey, scanID, obsTime, evID, sourceURL, srvID, reason, checks, tlsInfo, redirects)
		}

		if reqErr != nil {
			flowsErr = reqErr
			reason := common.SanitizeError(reqErr)
			degraded = append(degraded, "chatflows check failed: "+reason)
			checks = append(checks, common.CheckEntry{
				CheckID: CheckChatflows, Operation: CheckChatflows, Outcome: graph.OutcomeFailed,
				Reason: reason, OperationKind: graph.EnumerationOperation,
				Details: map[string]any{"error": reason},
			})
		} else {
			if hasFlowiseHeaders(resp.Header) {
				flowiseConfirmed = true
			}
			switch resp.StatusCode {
			case http.StatusOK:
				if resp.Truncated {
					responseTruncated = true
					degraded = append(degraded, "chatflows response truncated at max_response_bytes")
					checks = append(checks, common.CheckEntry{
						CheckID: CheckChatflows, Operation: CheckChatflows, Outcome: graph.OutcomeFailed,
						Reason: "chatflows response truncated at max_response_bytes limit", OperationKind: graph.EnumerationOperation,
						Details: map[string]any{"http_status": resp.StatusCode, "truncated": true},
					})
				} else {
					var parsed []chatflowEntry
					if err := json.Unmarshal(resp.Body, &parsed); err != nil || parsed == nil {
						degraded = append(degraded, "invalid JSON array from /api/v1/chatflows")
						checks = append(checks, common.CheckEntry{
							CheckID: CheckChatflows, Operation: CheckChatflows, Outcome: graph.OutcomeFailed,
							Reason: "invalid JSON array response from /api/v1/chatflows", OperationKind: graph.EnumerationOperation,
							Details: map[string]any{"http_status": resp.StatusCode},
						})
					} else if !flowiseConfirmed && !verSuccess && !hasFlowiseChatflowEvidence(parsed) {
						degraded = append(degraded, "chatflows response lacks Flowise identity evidence")
						checks = append(checks, common.CheckEntry{
							CheckID: CheckChatflows, Operation: CheckChatflows, Outcome: graph.OutcomeFailed,
							Reason: "chatflows array lacks Flowise evidence", OperationKind: graph.EnumerationOperation,
							Details: map[string]any{"http_status": resp.StatusCode},
						})
					} else {
						flowiseConfirmed = true
						flowsSuccess = true
						if len(parsed) > maxItems {
							flowsTruncated = true
							chatflows = parsed[:maxItems]
						} else {
							chatflows = parsed
						}
						for _, cf := range chatflows {
							if cf.IsPublic != nil && *cf.IsPublic {
								publicCount++
							}
						}
						checks = append(checks, common.CheckEntry{
							CheckID: CheckChatflows, Operation: CheckChatflows, Outcome: graph.OutcomeSuccess,
							Reason: "Flowise chatflows enumerated anonymously", Anonymous: true,
							OperationKind: graph.EnumerationOperation, CountForAccess: true,
							Details: map[string]any{
								"http_status":           resp.StatusCode,
								"chatflow_count":        len(chatflows),
								"public_chatflow_count": publicCount,
								"truncated":             flowsTruncated,
							},
						})
					}
				}
			case http.StatusUnauthorized, http.StatusForbidden:
				flowsDenied = true
				if hasFlowiseDenial(resp.Header, resp.Body) || verSuccess {
					flowiseConfirmed = true
					deniedConfirmed = true
				}
				degraded = append(degraded, fmt.Sprintf("chatflows denied (HTTP %d)", resp.StatusCode))
				checks = append(checks, common.CheckEntry{
					CheckID: CheckChatflows, Operation: CheckChatflows, Outcome: graph.OutcomeDenied,
					Reason:        fmt.Sprintf("HTTP %d: authentication or authorization required", resp.StatusCode),
					OperationKind: graph.EnumerationOperation,
					Details:       map[string]any{"http_status": resp.StatusCode},
				})
			case http.StatusNotFound:
				degraded = append(degraded, "chatflows endpoint unavailable (HTTP 404)")
				checks = append(checks, common.CheckEntry{
					CheckID: CheckChatflows, Operation: CheckChatflows, Outcome: graph.OutcomeFailed,
					Reason: "HTTP 404 not found (/api/v1/chatflows unavailable)", OperationKind: graph.EnumerationOperation,
					Details: map[string]any{"http_status": resp.StatusCode},
				})
			default:
				degraded = append(degraded, fmt.Sprintf("chatflows returned HTTP %d", resp.StatusCode))
				checks = append(checks, common.CheckEntry{
					CheckID: CheckChatflows, Operation: CheckChatflows, Outcome: graph.OutcomeFailed,
					Reason:        fmt.Sprintf("HTTP %d unexpected status", resp.StatusCode),
					OperationKind: graph.EnumerationOperation,
					Details:       map[string]any{"http_status": resp.StatusCode},
				})
			}
		}
	}

	// 3. Check: Bounded Flow Configuration Capture (content tier).
	var contentSummary *graph.ContentSummary
	var contentTruncated bool
	var contentTruncReasons []string
	if !c.cfg.Content.EnabledFor(Surface) {
		checks = append(checks, common.CheckEntry{
			CheckID: CheckFlowConfig, Operation: CheckFlowConfig, Outcome: graph.OutcomeSkipped,
			Reason: "content collection disabled by policy", OperationKind: graph.ResourceReadOperation,
			Details: map[string]any{"skipped": true, "policy": "content_disabled"},
		})
	} else if !flowsSuccess {
		checks = append(checks, common.CheckEntry{
			CheckID: CheckFlowConfig, Operation: CheckFlowConfig, Outcome: graph.OutcomeSkipped,
			Reason: "prerequisite failed: chatflows listing unavailable", OperationKind: graph.ResourceReadOperation,
		})
	} else {
		budget := content.NewBudget(c.cfg.Content, secrets.NewRedactor(c.cfg.Secrets))
		captured := 0
		for idx, cf := range chatflows {
			trimmed := strings.TrimSpace(cf.FlowData)
			if trimmed == "" || content.LooksBinary([]byte(trimmed)) {
				continue
			}
			if ok, _ := budget.ClaimResourceItem("chatflows"); !ok {
				break
			}
			loc := cf.ID
			if loc == "" {
				loc = cf.Name
			}
			if loc == "" {
				loc = fmt.Sprintf("chatflow-%d", idx)
			}
			rec, added, addErr := budget.Add(content.RecordInput{
				DeploymentScope: scope,
				ScanID:          scanID,
				VantageKey:      vantageKey,
				ServiceID:       srvID.ID(),
				Surface:         Surface,
				CheckID:         CheckFlowConfig,
				Source:          sourceURL,
				Kind:            content.KindFlow,
				Location:        loc,
				MediaType:       "application/json",
				ObservedAt:      obsTime,
				Body:            trimmed,
			})
			if addErr != nil {
				return checkpoint.Result{}, fmt.Errorf("create flowise flow content record: %w", addErr)
			}
			if added {
				captured++
				if c.contentSink != nil {
					if err := c.contentSink.Write(rec); err != nil {
						return checkpoint.Result{}, fmt.Errorf("write flowise flow content record: %w", err)
					}
				}
			}
		}
		contentTruncated = budget.Truncated()
		contentTruncReasons = budget.Reasons()
		if captured > 0 || len(budget.Findings()) > 0 || contentTruncated {
			cfgFlag := captured > 0
			contentSummary = common.ContentSummaryFromBudget(budget, obsTime, nil, &cfgFlag)
		}
		if captured > 0 {
			details := map[string]any{
				"chatflows_captured": captured,
				"content_items":      len(budget.Records()),
				"content_bytes":      budget.Bytes(),
				"content_truncated":  contentTruncated,
			}
			if found := budget.Findings(); len(found) > 0 {
				details["detected_exposures"] = content.ExposureDetails(found)
			}
			checks = append(checks, common.CheckEntry{
				CheckID: CheckFlowConfig, Operation: CheckFlowConfig, Outcome: graph.OutcomeSuccess,
				Reason:        fmt.Sprintf("bounded Flowise flow configs captured (%d items)", captured),
				OperationKind: graph.ResourceReadOperation, CountForAccess: false, Details: details,
			})
		} else {
			checks = append(checks, common.CheckEntry{
				CheckID: CheckFlowConfig, Operation: CheckFlowConfig, Outcome: graph.OutcomeSkipped,
				Reason: "no flowData bodies present", OperationKind: graph.ResourceReadOperation,
			})
		}
	}

	var finalCoverage graph.Coverage
	var finalCoverageReason string
	var finalStatus checkpoint.TargetStatus

	switch {
	case verErr != nil && flowsErr != nil:
		finalCoverage = graph.CoverageFailed
		finalStatus = checkpoint.TargetStatusFailed
		finalCoverageReason = "target unreachable: " + common.SanitizeError(verErr)
	case !flowiseConfirmed:
		finalCoverage = graph.CoverageFailed
		finalStatus = checkpoint.TargetStatusFailed
		finalCoverageReason = "enumeration failed: target not confirmed as Flowise"
	case verSuccess && flowsSuccess:
		if flowsTruncated || responseTruncated || contentTruncated {
			finalCoverage = graph.CoverageTruncated
			finalStatus = checkpoint.TargetStatusPartial
			finalCoverageReason = flowiseTruncationReason(flowsTruncated, responseTruncated, contentTruncReasons)
		} else {
			finalCoverage = graph.CoverageComplete
			finalStatus = checkpoint.TargetStatusCompleted
		}
	case flowsSuccess || (verSuccess && flowsDenied):
		if flowsTruncated || responseTruncated || contentTruncated {
			finalCoverage = graph.CoverageTruncated
			finalStatus = checkpoint.TargetStatusPartial
			finalCoverageReason = flowiseTruncationReason(flowsTruncated, responseTruncated, contentTruncReasons)
		} else {
			finalCoverage = graph.CoveragePartial
			finalStatus = checkpoint.TargetStatusPartial
			finalCoverageReason = strings.Join(degraded, "; ")
		}
	case deniedConfirmed && (verDenied || flowsDenied):
		finalCoverage = graph.CoveragePartial
		finalStatus = checkpoint.TargetStatusPartial
		finalCoverageReason = "authentication required on Flowise endpoint"
	default:
		finalCoverage = graph.CoverageFailed
		finalStatus = checkpoint.TargetStatusFailed
		finalCoverageReason = "enumeration failed: target not confirmed as Flowise"
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
			Endpoint:         ep,
			Name:             fmt.Sprintf("Flowise · %s:%d", ep.Host(), ep.Port()),
			Product:          "Flowise",
			Vendor:           "FlowiseAI",
			VantageKey:       vantageKey,
			Access:           access,
			ExecSurface:      []string{graph.ExecWorkflowExec},
			ExecSurfaceBasis: graph.BasisInferred,
			TLS:              common.TLSSummary(tlsInfo),
			Content:          contentSummary,
		}
		srvProps := facts.Properties()
		if normVersion != "" {
			srvProps["software_version"] = normVersion
		}
		if rawVersion != "" {
			srvProps["software_version_raw"] = rawVersion
		}
		if flowsSuccess {
			srvProps["chatflow_count"] = len(chatflows)
			srvProps["public_chatflow_count"] = publicCount
		}

		srvNode, err := graph.NewNode(srvID, obs)
		if err != nil {
			return checkpoint.Result{}, fmt.Errorf("create FlowiseInstance node: %w", err)
		}
		srvItem, err := emitter.NewNodeItem(srvNode, srvProps)
		if err != nil {
			return checkpoint.Result{}, fmt.Errorf("create FlowiseInstance node item: %w", err)
		}
		nodes = append(nodes, srvItem)

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

		method := CheckVersion
		confidence := "exact"
		if !verSuccess {
			if flowsSuccess {
				method = CheckChatflows
			} else {
				method = "denied_response"
				confidence = "inferred"
			}
		}
		fpInput = &evidence.FingerprintInput{
			TargetID:           srvID.ID(),
			Product:            "Flowise",
			Vendor:             "FlowiseAI",
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

func hasFlowiseHeaders(h http.Header) bool {
	return strings.Contains(strings.ToLower(h.Get("Server")), "flowise")
}

func hasFlowiseDenial(h http.Header, body []byte) bool {
	if hasFlowiseHeaders(h) {
		return true
	}
	b := strings.ToLower(string(body))
	www := strings.ToLower(h.Get("Www-Authenticate"))
	return strings.Contains(b, "flowise") || strings.Contains(www, "flowise")
}

func hasFlowiseChatflowEvidence(entries []chatflowEntry) bool {
	for _, e := range entries {
		if e.FlowData != "" || e.IsPublic != nil || e.Deployed != nil {
			return true
		}
	}
	return false
}

func flowiseTruncationReason(flowsTrunc, respTrunc bool, contentReasons []string) string {
	var parts []string
	if flowsTrunc {
		parts = append(parts, "chatflow listing truncated at max_items bound")
	}
	if respTrunc {
		parts = append(parts, "response body truncated at max_response_bytes bound")
	}
	parts = append(parts, contentReasons...)
	return strings.Join(parts, "; ")
}
