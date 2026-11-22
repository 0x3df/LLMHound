// Package langflow provides anonymous, read-only metadata enumeration of
// Langflow endpoints (/api/v1/version, /api/v1/auto_login, /api/v1/flows/,
// /api/v1/all) and bounded flow definition capture without ever executing
// flows, validating code, or retaining any auto-login token values.
package langflow

import (
	"bytes"
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
	// Surface is the canonical surface identifier for Langflow.
	Surface = "langflow"

	// DefaultPort is the default listener port for Langflow.
	DefaultPort = 7860

	// Allowlisted check identifiers.
	CheckVersion    = "langflow_version"
	CheckAutoLogin  = "langflow_auto_login"
	CheckFlows      = "langflow_flows"
	CheckComponents = "langflow_components"
	CheckFlowBodies = "langflow_flow_bodies"
)

type versionResponse struct {
	Version     string `json:"version"`
	MainVersion string `json:"main_version"`
	Package     string `json:"package"`
}

// autoLoginResponse deliberately decodes ONLY posture metadata and ignores
// access_token / refresh_token so credentials are never retained in memory.
type autoLoginResponse struct {
	TokenType string `json:"token_type"`
	AutoLogin *bool  `json:"auto_login"`
}

type flowEntry struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Data        json.RawMessage `json:"data,omitempty"`
}

// Collector implements anonymous, read-only Langflow enumeration.
type Collector struct {
	cfg         config.Config
	transport   *transport.Client
	contentSink content.Sink
}

// Option configures a Langflow Collector.
type Option func(*Collector)

// WithTransport overrides the transport client (primarily for testing).
func WithTransport(tc *transport.Client) Option {
	return func(c *Collector) {
		c.transport = tc
	}
}

// WithContentSink configures where bounded flow definitions are written.
func WithContentSink(sink content.Sink) Option {
	return func(c *Collector) {
		c.contentSink = sink
	}
}

// New constructs a Langflow collector with the given configuration.
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

// Collect performs allowlisted GET metadata checks and bounded flow definition
// capture on a Langflow server without executing flows or storing tokens.
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

	srvID, err := graph.NewServiceIdentity(scope, graph.LangflowInstance, ep)
	if err != nil {
		return checkpoint.Result{}, fmt.Errorf("create service identity: %w", err)
	}

	evID := common.EvidenceID(scanID, srvID.ID(), obsTime)
	baseURL := strings.TrimSuffix(ep.String(), "/")
	sourceURL := baseURL + "/api/v1/flows/"

	var tlsInfo *transport.TLSInfo
	var redirects []transport.RedirectInfo
	var checks []common.CheckEntry
	var degraded []string

	var langflowConfirmed bool
	var deniedConfirmed bool
	var rawVersion, normVersion string
	var verSuccess, verDenied bool
	var verErr error

	var autoLoginEnabled *bool
	var authAdvertised string
	var autoLoginSuccess, autoLoginDenied bool
	var autoLoginErr error

	var flows []flowEntry
	var flowsSuccess, flowsDenied, flowsTruncated bool
	var flowsErr error

	var componentsSuccess, componentsDenied bool
	var componentCount *int
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
				common.CheckEntry{CheckID: CheckAutoLogin, Operation: CheckAutoLogin, Outcome: graph.OutcomeSkipped, Reason: "prerequisite failed: TLS verification failed", OperationKind: graph.EnumerationOperation},
				common.CheckEntry{CheckID: CheckFlows, Operation: CheckFlows, Outcome: graph.OutcomeSkipped, Reason: "prerequisite failed: TLS verification failed", OperationKind: graph.EnumerationOperation},
				common.CheckEntry{CheckID: CheckComponents, Operation: CheckComponents, Outcome: graph.OutcomeSkipped, Reason: "prerequisite failed: TLS verification failed", OperationKind: graph.EnumerationOperation},
				common.CheckEntry{CheckID: CheckFlowBodies, Operation: CheckFlowBodies, Outcome: graph.OutcomeSkipped, Reason: "prerequisite failed: TLS verification failed", OperationKind: graph.ResourceReadOperation},
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
					if err := json.Unmarshal(resp.Body, &v); err != nil || !isLangflowVersion(v) {
						degraded = append(degraded, "/api/v1/version lacks Langflow evidence")
						checks = append(checks, common.CheckEntry{
							CheckID: CheckVersion, Operation: CheckVersion, Outcome: graph.OutcomeFailed,
							Reason: "invalid JSON or non-Langflow response from /api/v1/version", OperationKind: graph.EnumerationOperation,
							Details: map[string]any{"http_status": resp.StatusCode},
						})
					} else {
						langflowConfirmed = true
						verSuccess = true
						rawVer := strings.TrimSpace(v.Version)
						if rawVer == "" {
							rawVer = strings.TrimSpace(v.MainVersion)
						}
						rawVersion = common.BoundString(rawVer, 128)
						normVersion = common.NormalizeVersion(rawVer)
						checks = append(checks, common.CheckEntry{
							CheckID: CheckVersion, Operation: CheckVersion, Outcome: graph.OutcomeSuccess,
							Reason: fmt.Sprintf("Langflow version reported: %s", rawVersion), Anonymous: true,
							OperationKind: graph.EnumerationOperation, CountForAccess: false,
							Details: map[string]any{
								"http_status":          resp.StatusCode,
								"software_version":     normVersion,
								"software_version_raw": rawVersion,
								"package":              common.BoundString(v.Package, 64),
							},
						})
					}
				}
			case http.StatusUnauthorized, http.StatusForbidden:
				verDenied = true
				if hasLangflowDenial(resp.Header, resp.Body) {
					langflowConfirmed = true
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
			case http.StatusTooManyRequests:
				degraded = append(degraded, "version rate limited (HTTP 429)")
				checks = append(checks, common.CheckEntry{
					CheckID: CheckVersion, Operation: CheckVersion, Outcome: graph.OutcomeFailed,
					Reason: "HTTP 429 rate limited", OperationKind: graph.EnumerationOperation,
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

	// 2. Check: GET /api/v1/auto_login (posture check; NEVER retain access_token/refresh_token).
	{
		resp, reqErr := c.transport.Get(ctx, baseURL+"/api/v1/auto_login")
		common.AbsorbTransport(resp, &tlsInfo, &redirects)

		if common.IsTLSFailure(tlsInfo, c.cfg.Insecure) {
			reason := common.SanitizeError(reqErr)
			if reason == "" {
				reason = "TLS certificate verification failed: " + common.BoundString(tlsInfo.VerificationReason, 200)
			}
			checks = append(checks,
				common.CheckEntry{
					CheckID: CheckAutoLogin, Operation: CheckAutoLogin, Outcome: graph.OutcomeFailed,
					Reason: reason, OperationKind: graph.EnumerationOperation,
					Details: map[string]any{"tls_error": common.BoundString(tlsInfo.VerificationReason, 200)},
				},
				common.CheckEntry{CheckID: CheckFlows, Operation: CheckFlows, Outcome: graph.OutcomeSkipped, Reason: "prerequisite failed: TLS verification failed", OperationKind: graph.EnumerationOperation},
				common.CheckEntry{CheckID: CheckComponents, Operation: CheckComponents, Outcome: graph.OutcomeSkipped, Reason: "prerequisite failed: TLS verification failed", OperationKind: graph.EnumerationOperation},
				common.CheckEntry{CheckID: CheckFlowBodies, Operation: CheckFlowBodies, Outcome: graph.OutcomeSkipped, Reason: "prerequisite failed: TLS verification failed", OperationKind: graph.ResourceReadOperation},
			)
			return c.buildFailedResult(target, scope, vantageKey, scanID, obsTime, evID, baseURL+"/api/v1/auto_login", srvID, reason, checks, tlsInfo, redirects)
		}

		if reqErr != nil {
			autoLoginErr = reqErr
			reason := common.SanitizeError(reqErr)
			degraded = append(degraded, "auto_login check failed: "+reason)
			checks = append(checks, common.CheckEntry{
				CheckID: CheckAutoLogin, Operation: CheckAutoLogin, Outcome: graph.OutcomeFailed,
				Reason: reason, OperationKind: graph.EnumerationOperation,
				Details: map[string]any{"error": reason},
			})
		} else {
			switch resp.StatusCode {
			case http.StatusOK:
				if resp.Truncated {
					responseTruncated = true
					degraded = append(degraded, "auto_login response truncated at max_response_bytes")
					checks = append(checks, common.CheckEntry{
						CheckID: CheckAutoLogin, Operation: CheckAutoLogin, Outcome: graph.OutcomeFailed,
						Reason: "auto_login response truncated at max_response_bytes limit", OperationKind: graph.EnumerationOperation,
						Details: map[string]any{"http_status": resp.StatusCode, "truncated": true},
					})
				} else {
					var al autoLoginResponse
					if err := json.Unmarshal(resp.Body, &al); err != nil || (strings.TrimSpace(al.TokenType) == "" && al.AutoLogin == nil) {
						degraded = append(degraded, "invalid JSON in /api/v1/auto_login")
						checks = append(checks, common.CheckEntry{
							CheckID: CheckAutoLogin, Operation: CheckAutoLogin, Outcome: graph.OutcomeFailed,
							Reason: "invalid JSON response from /api/v1/auto_login", OperationKind: graph.EnumerationOperation,
							Details: map[string]any{"http_status": resp.StatusCode},
						})
					} else if al.AutoLogin != nil && !*al.AutoLogin {
						langflowConfirmed = true
						autoLoginDenied = true
						fVal := false
						autoLoginEnabled = &fVal
						authAdvertised = "required"
						degraded = append(degraded, "auto_login disabled")
						checks = append(checks, common.CheckEntry{
							CheckID: CheckAutoLogin, Operation: CheckAutoLogin, Outcome: graph.OutcomeDenied,
							Reason: "Langflow auto_login is disabled", OperationKind: graph.EnumerationOperation,
							Details: map[string]any{"http_status": resp.StatusCode, "auto_login_enabled": false},
						})
					} else {
						langflowConfirmed = true
						autoLoginSuccess = true
						tVal := true
						autoLoginEnabled = &tVal
						authAdvertised = "none"
						checks = append(checks, common.CheckEntry{
							CheckID: CheckAutoLogin, Operation: CheckAutoLogin, Outcome: graph.OutcomeSuccess,
							Reason: "Langflow auto_login enabled anonymously (token discarded)", Anonymous: true,
							OperationKind: graph.EnumerationOperation, CountForAccess: true,
							Details: map[string]any{"http_status": resp.StatusCode, "auto_login_enabled": true},
						})
					}
				}
			case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden:
				autoLoginDenied = true
				fVal := false
				autoLoginEnabled = &fVal
				authAdvertised = "required"
				if hasLangflowDenial(resp.Header, resp.Body) {
					langflowConfirmed = true
					deniedConfirmed = true
				}
				degraded = append(degraded, fmt.Sprintf("auto_login disabled/denied (HTTP %d)", resp.StatusCode))
				checks = append(checks, common.CheckEntry{
					CheckID: CheckAutoLogin, Operation: CheckAutoLogin, Outcome: graph.OutcomeDenied,
					Reason:        fmt.Sprintf("HTTP %d: auto_login disabled or authentication required", resp.StatusCode),
					OperationKind: graph.EnumerationOperation,
					Details:       map[string]any{"http_status": resp.StatusCode, "auto_login_enabled": false},
				})
			case http.StatusNotFound:
				degraded = append(degraded, "auto_login endpoint unavailable (HTTP 404)")
				checks = append(checks, common.CheckEntry{
					CheckID: CheckAutoLogin, Operation: CheckAutoLogin, Outcome: graph.OutcomeFailed,
					Reason: "HTTP 404 not found (/api/v1/auto_login unavailable)", OperationKind: graph.EnumerationOperation,
					Details: map[string]any{"http_status": resp.StatusCode},
				})
			default:
				degraded = append(degraded, fmt.Sprintf("auto_login returned HTTP %d", resp.StatusCode))
				checks = append(checks, common.CheckEntry{
					CheckID: CheckAutoLogin, Operation: CheckAutoLogin, Outcome: graph.OutcomeFailed,
					Reason:        fmt.Sprintf("HTTP %d unexpected status", resp.StatusCode),
					OperationKind: graph.EnumerationOperation,
					Details:       map[string]any{"http_status": resp.StatusCode},
				})
			}
		}
	}

	// 3. Check: GET /api/v1/flows/ (enumeration check).
	{
		resp, reqErr := c.transport.Get(ctx, sourceURL)
		common.AbsorbTransport(resp, &tlsInfo, &redirects)

		if common.IsTLSFailure(tlsInfo, c.cfg.Insecure) {
			reason := common.SanitizeError(reqErr)
			if reason == "" {
				reason = "TLS certificate verification failed: " + common.BoundString(tlsInfo.VerificationReason, 200)
			}
			checks = append(checks,
				common.CheckEntry{
					CheckID: CheckFlows, Operation: CheckFlows, Outcome: graph.OutcomeFailed,
					Reason: reason, OperationKind: graph.EnumerationOperation,
					Details: map[string]any{"tls_error": common.BoundString(tlsInfo.VerificationReason, 200)},
				},
				common.CheckEntry{CheckID: CheckComponents, Operation: CheckComponents, Outcome: graph.OutcomeSkipped, Reason: "prerequisite failed: TLS verification failed", OperationKind: graph.EnumerationOperation},
				common.CheckEntry{CheckID: CheckFlowBodies, Operation: CheckFlowBodies, Outcome: graph.OutcomeSkipped, Reason: "prerequisite failed: TLS verification failed", OperationKind: graph.ResourceReadOperation},
			)
			return c.buildFailedResult(target, scope, vantageKey, scanID, obsTime, evID, sourceURL, srvID, reason, checks, tlsInfo, redirects)
		}

		if reqErr != nil {
			flowsErr = reqErr
			reason := common.SanitizeError(reqErr)
			degraded = append(degraded, "flows check failed: "+reason)
			checks = append(checks, common.CheckEntry{
				CheckID: CheckFlows, Operation: CheckFlows, Outcome: graph.OutcomeFailed,
				Reason: reason, OperationKind: graph.EnumerationOperation,
				Details: map[string]any{"error": reason},
			})
		} else {
			switch resp.StatusCode {
			case http.StatusOK:
				if resp.Truncated {
					responseTruncated = true
					degraded = append(degraded, "flows response truncated at max_response_bytes")
					checks = append(checks, common.CheckEntry{
						CheckID: CheckFlows, Operation: CheckFlows, Outcome: graph.OutcomeFailed,
						Reason: "flows response truncated at max_response_bytes limit", OperationKind: graph.EnumerationOperation,
						Details: map[string]any{"http_status": resp.StatusCode, "truncated": true},
					})
				} else {
					var parsed []flowEntry
					if err := json.Unmarshal(resp.Body, &parsed); err != nil || parsed == nil {
						degraded = append(degraded, "invalid JSON array from /api/v1/flows/")
						checks = append(checks, common.CheckEntry{
							CheckID: CheckFlows, Operation: CheckFlows, Outcome: graph.OutcomeFailed,
							Reason: "invalid JSON array response from /api/v1/flows/", OperationKind: graph.EnumerationOperation,
							Details: map[string]any{"http_status": resp.StatusCode},
						})
					} else if !langflowConfirmed {
						degraded = append(degraded, "flows list lacks Langflow identity evidence")
						checks = append(checks, common.CheckEntry{
							CheckID: CheckFlows, Operation: CheckFlows, Outcome: graph.OutcomeFailed,
							Reason: "flows list cannot establish Langflow identity alone", OperationKind: graph.EnumerationOperation,
							Details: map[string]any{"http_status": resp.StatusCode},
						})
					} else {
						flowsSuccess = true
						if len(parsed) > maxItems {
							flowsTruncated = true
							flows = parsed[:maxItems]
						} else {
							flows = parsed
						}
						checks = append(checks, common.CheckEntry{
							CheckID: CheckFlows, Operation: CheckFlows, Outcome: graph.OutcomeSuccess,
							Reason: "Langflow flows listed anonymously", Anonymous: true,
							OperationKind: graph.EnumerationOperation, CountForAccess: true,
							Details: map[string]any{
								"http_status": resp.StatusCode,
								"flow_count":  len(flows),
								"truncated":   flowsTruncated,
							},
						})
					}
				}
			case http.StatusUnauthorized, http.StatusForbidden:
				flowsDenied = true
				if hasLangflowDenial(resp.Header, resp.Body) {
					langflowConfirmed = true
					deniedConfirmed = true
				}
				degraded = append(degraded, fmt.Sprintf("flows denied (HTTP %d)", resp.StatusCode))
				checks = append(checks, common.CheckEntry{
					CheckID: CheckFlows, Operation: CheckFlows, Outcome: graph.OutcomeDenied,
					Reason:        fmt.Sprintf("HTTP %d: authentication or authorization required", resp.StatusCode),
					OperationKind: graph.EnumerationOperation,
					Details:       map[string]any{"http_status": resp.StatusCode},
				})
			case http.StatusNotFound:
				degraded = append(degraded, "flows endpoint unavailable (HTTP 404)")
				checks = append(checks, common.CheckEntry{
					CheckID: CheckFlows, Operation: CheckFlows, Outcome: graph.OutcomeFailed,
					Reason: "HTTP 404 not found (/api/v1/flows/ unavailable)", OperationKind: graph.EnumerationOperation,
					Details: map[string]any{"http_status": resp.StatusCode},
				})
			default:
				degraded = append(degraded, fmt.Sprintf("flows returned HTTP %d", resp.StatusCode))
				checks = append(checks, common.CheckEntry{
					CheckID: CheckFlows, Operation: CheckFlows, Outcome: graph.OutcomeFailed,
					Reason:        fmt.Sprintf("HTTP %d unexpected status", resp.StatusCode),
					OperationKind: graph.EnumerationOperation,
					Details:       map[string]any{"http_status": resp.StatusCode},
				})
			}
		}
	}

	// 4. Check: GET /api/v1/all (components catalog).
	if !langflowConfirmed {
		checks = append(checks, common.CheckEntry{
			CheckID: CheckComponents, Operation: CheckComponents, Outcome: graph.OutcomeSkipped,
			Reason: "prerequisite failed: Langflow identity not established", OperationKind: graph.EnumerationOperation,
		})
	} else {
		resp, reqErr := c.transport.Get(ctx, baseURL+"/api/v1/all")
		common.AbsorbTransport(resp, &tlsInfo, &redirects)
		if reqErr != nil {
			reason := common.SanitizeError(reqErr)
			degraded = append(degraded, "components check failed: "+reason)
			checks = append(checks, common.CheckEntry{
				CheckID: CheckComponents, Operation: CheckComponents, Outcome: graph.OutcomeFailed,
				Reason: reason, OperationKind: graph.EnumerationOperation,
				Details: map[string]any{"error": reason},
			})
		} else {
			switch resp.StatusCode {
			case http.StatusOK:
				if resp.Truncated {
					responseTruncated = true
					degraded = append(degraded, "components response truncated at max_response_bytes")
					checks = append(checks, common.CheckEntry{
						CheckID: CheckComponents, Operation: CheckComponents, Outcome: graph.OutcomeFailed,
						Reason: "components response truncated at max_response_bytes limit", OperationKind: graph.EnumerationOperation,
						Details: map[string]any{"http_status": resp.StatusCode, "truncated": true},
					})
				} else {
					var compMap map[string]map[string]json.RawMessage
					if err := json.Unmarshal(resp.Body, &compMap); err != nil {
						degraded = append(degraded, "invalid JSON in /api/v1/all")
						checks = append(checks, common.CheckEntry{
							CheckID: CheckComponents, Operation: CheckComponents, Outcome: graph.OutcomeFailed,
							Reason: "invalid JSON response from /api/v1/all", OperationKind: graph.EnumerationOperation,
							Details: map[string]any{"http_status": resp.StatusCode},
						})
					} else {
						componentsSuccess = true
						total := 0
						for _, cat := range compMap {
							total += len(cat)
						}
						componentCount = &total
						checks = append(checks, common.CheckEntry{
							CheckID: CheckComponents, Operation: CheckComponents, Outcome: graph.OutcomeSuccess,
							Reason: "Langflow components catalog enumerated anonymously", Anonymous: true,
							OperationKind: graph.EnumerationOperation, CountForAccess: true,
							Details: map[string]any{"http_status": resp.StatusCode, "component_count": total},
						})
					}
				}
			case http.StatusUnauthorized, http.StatusForbidden:
				componentsDenied = true
				degraded = append(degraded, fmt.Sprintf("components denied (HTTP %d)", resp.StatusCode))
				checks = append(checks, common.CheckEntry{
					CheckID: CheckComponents, Operation: CheckComponents, Outcome: graph.OutcomeDenied,
					Reason:        fmt.Sprintf("HTTP %d: authentication or authorization required", resp.StatusCode),
					OperationKind: graph.EnumerationOperation,
					Details:       map[string]any{"http_status": resp.StatusCode},
				})
			default:
				degraded = append(degraded, fmt.Sprintf("components returned HTTP %d", resp.StatusCode))
				checks = append(checks, common.CheckEntry{
					CheckID: CheckComponents, Operation: CheckComponents, Outcome: graph.OutcomeFailed,
					Reason:        fmt.Sprintf("HTTP %d unexpected status", resp.StatusCode),
					OperationKind: graph.EnumerationOperation,
					Details:       map[string]any{"http_status": resp.StatusCode},
				})
			}
		}
	}

	// 5. Check: Bounded Flow Body Content Capture (content tier).
	var contentSummary *graph.ContentSummary
	var contentTruncated bool
	var contentTruncReasons []string
	if !c.cfg.Content.EnabledFor(Surface) {
		checks = append(checks, common.CheckEntry{
			CheckID: CheckFlowBodies, Operation: CheckFlowBodies, Outcome: graph.OutcomeSkipped,
			Reason: "content collection disabled by policy", OperationKind: graph.ResourceReadOperation,
			Details: map[string]any{"skipped": true, "policy": "content_disabled"},
		})
	} else if !flowsSuccess {
		checks = append(checks, common.CheckEntry{
			CheckID: CheckFlowBodies, Operation: CheckFlowBodies, Outcome: graph.OutcomeSkipped,
			Reason: "prerequisite failed: flows listing unavailable", OperationKind: graph.ResourceReadOperation,
		})
	} else {
		budget := content.NewBudget(c.cfg.Content, secrets.NewRedactor(c.cfg.Secrets))
		captured := 0
		for idx, fl := range flows {
			trimmed := bytes.TrimSpace(fl.Data)
			if len(trimmed) == 0 || string(trimmed) == "null" || content.LooksBinary(trimmed) {
				continue
			}
			if ok, _ := budget.ClaimResourceItem("flows"); !ok {
				break
			}
			loc := fl.ID
			if loc == "" {
				loc = fl.Name
			}
			if loc == "" {
				loc = fmt.Sprintf("flow-%d", idx)
			}
			rec, added, addErr := budget.Add(content.RecordInput{
				DeploymentScope: scope,
				ScanID:          scanID,
				VantageKey:      vantageKey,
				ServiceID:       srvID.ID(),
				Surface:         Surface,
				CheckID:         CheckFlowBodies,
				Source:          sourceURL,
				Kind:            content.KindFlow,
				Location:        loc,
				MediaType:       "application/json",
				ObservedAt:      obsTime,
				Body:            string(trimmed),
			})
			if addErr != nil {
				return checkpoint.Result{}, fmt.Errorf("create langflow flow content record: %w", addErr)
			}
			if added {
				captured++
				if c.contentSink != nil {
					if err := c.contentSink.Write(rec); err != nil {
						return checkpoint.Result{}, fmt.Errorf("write langflow flow content record: %w", err)
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
				"flows_captured":    captured,
				"content_items":     len(budget.Records()),
				"content_bytes":     budget.Bytes(),
				"content_truncated": contentTruncated,
			}
			if found := budget.Findings(); len(found) > 0 {
				details["detected_exposures"] = content.ExposureDetails(found)
			}
			checks = append(checks, common.CheckEntry{
				CheckID: CheckFlowBodies, Operation: CheckFlowBodies, Outcome: graph.OutcomeSuccess,
				Reason:        fmt.Sprintf("bounded Langflow flow bodies captured (%d items)", captured),
				OperationKind: graph.ResourceReadOperation, CountForAccess: false, Details: details,
			})
		} else {
			checks = append(checks, common.CheckEntry{
				CheckID: CheckFlowBodies, Operation: CheckFlowBodies, Outcome: graph.OutcomeSkipped,
				Reason: "no flow data bodies present", OperationKind: graph.ResourceReadOperation,
			})
		}
	}

	var finalCoverage graph.Coverage
	var finalCoverageReason string
	var finalStatus checkpoint.TargetStatus

	allUnreachable := verErr != nil && autoLoginErr != nil && flowsErr != nil
	switch {
	case allUnreachable:
		finalCoverage = graph.CoverageFailed
		finalStatus = checkpoint.TargetStatusFailed
		finalCoverageReason = "target unreachable: " + common.SanitizeError(verErr)
	case !langflowConfirmed:
		finalCoverage = graph.CoverageFailed
		finalStatus = checkpoint.TargetStatusFailed
		finalCoverageReason = "enumeration failed: target not confirmed as Langflow"
	case verSuccess && autoLoginSuccess && flowsSuccess && componentsSuccess:
		if flowsTruncated || responseTruncated || contentTruncated {
			finalCoverage = graph.CoverageTruncated
			finalStatus = checkpoint.TargetStatusPartial
			finalCoverageReason = langflowTruncationReason(flowsTruncated, responseTruncated, contentTruncReasons)
		} else {
			finalCoverage = graph.CoverageComplete
			finalStatus = checkpoint.TargetStatusCompleted
		}
	case verSuccess || autoLoginSuccess || flowsSuccess || componentsSuccess:
		if flowsTruncated || responseTruncated || contentTruncated {
			finalCoverage = graph.CoverageTruncated
			finalStatus = checkpoint.TargetStatusPartial
			finalCoverageReason = langflowTruncationReason(flowsTruncated, responseTruncated, contentTruncReasons)
		} else {
			finalCoverage = graph.CoveragePartial
			finalStatus = checkpoint.TargetStatusPartial
			if len(degraded) > 0 {
				finalCoverageReason = strings.Join(degraded, "; ")
			} else {
				finalCoverageReason = "partial Langflow metadata collected"
			}
		}
	case deniedConfirmed && (verDenied || autoLoginDenied || flowsDenied || componentsDenied):
		finalCoverage = graph.CoveragePartial
		finalStatus = checkpoint.TargetStatusPartial
		finalCoverageReason = "authentication required on Langflow endpoint"
	default:
		finalCoverage = graph.CoverageFailed
		finalStatus = checkpoint.TargetStatusFailed
		finalCoverageReason = "enumeration failed: target not confirmed as Langflow"
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
			Name:             fmt.Sprintf("Langflow · %s:%d", ep.Host(), ep.Port()),
			Product:          "Langflow",
			Vendor:           "DataStax",
			VantageKey:       vantageKey,
			Access:           access,
			AuthAdvertised:   authAdvertised,
			ExecSurface:      []string{graph.ExecCodeEval, graph.ExecWorkflowExec},
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
		if autoLoginEnabled != nil {
			srvProps["auto_login_enabled"] = *autoLoginEnabled
		}
		if flowsSuccess {
			srvProps["flow_count"] = len(flows)
		}
		if componentCount != nil {
			srvProps["component_count"] = *componentCount
		}

		srvNode, err := graph.NewNode(srvID, obs)
		if err != nil {
			return checkpoint.Result{}, fmt.Errorf("create LangflowInstance node: %w", err)
		}
		srvItem, err := emitter.NewNodeItem(srvNode, srvProps)
		if err != nil {
			return checkpoint.Result{}, fmt.Errorf("create LangflowInstance node item: %w", err)
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
			if autoLoginSuccess {
				method = CheckAutoLogin
			} else {
				method = "denied_response"
				confidence = "inferred"
			}
		}
		fpInput = &evidence.FingerprintInput{
			TargetID:           srvID.ID(),
			Product:            "Langflow",
			Vendor:             "DataStax",
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

func isLangflowVersion(v versionResponse) bool {
	if strings.Contains(strings.ToLower(v.Package), "langflow") {
		return true
	}
	return strings.TrimSpace(v.MainVersion) != "" && strings.TrimSpace(v.Version) != ""
}

func hasLangflowDenial(h http.Header, body []byte) bool {
	b := strings.ToLower(string(body))
	www := strings.ToLower(h.Get("Www-Authenticate"))
	return strings.Contains(b, "langflow") || strings.Contains(www, "langflow")
}

func langflowTruncationReason(flowsTrunc, respTrunc bool, contentReasons []string) string {
	var parts []string
	if flowsTrunc {
		parts = append(parts, "flow listing truncated at max_items bound")
	}
	if respTrunc {
		parts = append(parts, "response body truncated at max_response_bytes bound")
	}
	parts = append(parts, contentReasons...)
	return strings.Join(parts, "; ")
}
