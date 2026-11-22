// Package openwebui provides anonymous, read-only metadata enumeration of
// Open WebUI instances (/api/version, /api/config, /api/models) and bounded
// configuration content capture without authenticating or mutating state.
package openwebui

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
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
	// Surface is the canonical surface identifier for Open WebUI.
	Surface = "open_webui"

	// DefaultPort is the default listener port for Open WebUI.
	DefaultPort = 3000

	// Allowlisted check identifiers.
	CheckVersion       = "open_webui_version"
	CheckConfig        = "open_webui_config"
	CheckModels        = "open_webui_models"
	CheckConfigContent = "open_webui_config_content"
)

type versionResponse struct {
	Version string `json:"version"`
}

type configResponse struct {
	Status     *bool  `json:"status,omitempty"`
	Name       string `json:"name,omitempty"`
	Version    string `json:"version,omitempty"`
	Onboarding *bool  `json:"onboarding,omitempty"`
	Features   *struct {
		Auth         *bool `json:"auth,omitempty"`
		EnableSignup *bool `json:"enable_signup,omitempty"`
	} `json:"features,omitempty"`
	DefaultModels     any      `json:"default_models,omitempty"`
	OllamaBaseURLs    []string `json:"ollama_base_urls,omitempty"`
	OpenAIAPIBaseURLs []string `json:"openai_api_base_urls,omitempty"`
	BackendURLs       []string `json:"backend_urls,omitempty"`
}

type modelsResponse struct {
	Data []struct {
		ID      string `json:"id"`
		Name    string `json:"name,omitempty"`
		OwnedBy string `json:"owned_by,omitempty"`
	} `json:"data"`
}

type parsedModel struct {
	ID      string
	Name    string
	OwnedBy string
}

// Collector implements anonymous, read-only Open WebUI enumeration.
type Collector struct {
	cfg         config.Config
	transport   *transport.Client
	contentSink content.Sink
}

// Option configures an Open WebUI Collector.
type Option func(*Collector)

// WithTransport overrides the transport client (primarily for testing).
func WithTransport(tc *transport.Client) Option {
	return func(c *Collector) {
		c.transport = tc
	}
}

// WithContentSink configures where bounded content-tier configuration bodies are written.
func WithContentSink(sink content.Sink) Option {
	return func(c *Collector) {
		c.contentSink = sink
	}
}

// New constructs an Open WebUI collector with the given configuration.
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

// Collect performs allowlisted GET metadata checks and optional bounded
// configuration content capture on an Open WebUI target.
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

	srvID, err := graph.NewServiceIdentity(scope, graph.OpenWebUIInstance, ep)
	if err != nil {
		return checkpoint.Result{}, fmt.Errorf("create service identity: %w", err)
	}

	evID := common.EvidenceID(scanID, srvID.ID(), obsTime)
	baseURL := strings.TrimSuffix(ep.String(), "/")
	configURL := baseURL + "/api/config"

	var tlsInfo *transport.TLSInfo
	var redirects []transport.RedirectInfo
	var checks []common.CheckEntry
	var degraded []string

	var openWebUIConfirmed bool
	var deniedConfirmed bool
	var rawVersion, normVersion string
	var verSuccess, verDenied bool
	var verErr error

	var cfgSuccess, cfgDenied bool
	var cfgErr error
	var cfgBody []byte
	var authAdvertised string
	var signupEnabled *bool
	backendSet := make(map[string]bool)

	var models []parsedModel
	var modelsSuccess, modelsDenied, modelsTruncated bool
	var modelsErr error
	var responseTruncated bool

	// 1. Check: GET /api/version (metadata only; never counts as anon_operations).
	{
		resp, reqErr := c.transport.Get(ctx, baseURL+"/api/version")
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
				common.CheckEntry{CheckID: CheckConfig, Operation: CheckConfig, Outcome: graph.OutcomeSkipped, Reason: "prerequisite failed: TLS verification failed", OperationKind: graph.EnumerationOperation},
				common.CheckEntry{CheckID: CheckModels, Operation: CheckModels, Outcome: graph.OutcomeSkipped, Reason: "prerequisite failed: TLS verification failed", OperationKind: graph.EnumerationOperation},
				common.CheckEntry{CheckID: CheckConfigContent, Operation: CheckConfigContent, Outcome: graph.OutcomeSkipped, Reason: "prerequisite failed: TLS verification failed", OperationKind: graph.ResourceReadOperation},
			)
			return c.buildFailedResult(target, scope, vantageKey, scanID, obsTime, evID, baseURL+"/api/version", srvID, reason, checks, tlsInfo, redirects)
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
			if hasOpenWebUIHeaders(resp.Header) {
				openWebUIConfirmed = true
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
						degraded = append(degraded, "invalid JSON or missing version in /api/version")
						checks = append(checks, common.CheckEntry{
							CheckID: CheckVersion, Operation: CheckVersion, Outcome: graph.OutcomeFailed,
							Reason: "invalid JSON or missing version in /api/version", OperationKind: graph.EnumerationOperation,
							Details: map[string]any{"http_status": resp.StatusCode},
						})
					} else {
						rawVersion = common.BoundString(v.Version, 128)
						normVersion = common.NormalizeVersion(v.Version)
						verSuccess = true
						checks = append(checks, common.CheckEntry{
							CheckID: CheckVersion, Operation: CheckVersion, Outcome: graph.OutcomeSuccess,
							Reason: fmt.Sprintf("version reported: %s", rawVersion), Anonymous: true,
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
				if hasOpenWebUIDenial(resp.Header, resp.Body) {
					openWebUIConfirmed = true
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
					Reason: "HTTP 404 not found (/api/version unavailable)", OperationKind: graph.EnumerationOperation,
					Details: map[string]any{"http_status": resp.StatusCode},
				})
			case http.StatusTooManyRequests:
				degraded = append(degraded, "version endpoint rate limited (HTTP 429)")
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

	// 2. Check: GET /api/config (public configuration metadata; never counts as anon_operations).
	{
		resp, reqErr := c.transport.Get(ctx, configURL)
		common.AbsorbTransport(resp, &tlsInfo, &redirects)

		if common.IsTLSFailure(tlsInfo, c.cfg.Insecure) {
			reason := common.SanitizeError(reqErr)
			if reason == "" {
				reason = "TLS certificate verification failed: " + common.BoundString(tlsInfo.VerificationReason, 200)
			}
			checks = append(checks,
				common.CheckEntry{
					CheckID: CheckConfig, Operation: CheckConfig, Outcome: graph.OutcomeFailed,
					Reason: reason, OperationKind: graph.EnumerationOperation,
					Details: map[string]any{"tls_error": common.BoundString(tlsInfo.VerificationReason, 200)},
				},
				common.CheckEntry{CheckID: CheckModels, Operation: CheckModels, Outcome: graph.OutcomeSkipped, Reason: "prerequisite failed: TLS verification failed", OperationKind: graph.EnumerationOperation},
				common.CheckEntry{CheckID: CheckConfigContent, Operation: CheckConfigContent, Outcome: graph.OutcomeSkipped, Reason: "prerequisite failed: TLS verification failed", OperationKind: graph.ResourceReadOperation},
			)
			return c.buildFailedResult(target, scope, vantageKey, scanID, obsTime, evID, configURL, srvID, reason, checks, tlsInfo, redirects)
		}

		if reqErr != nil {
			cfgErr = reqErr
			reason := common.SanitizeError(reqErr)
			degraded = append(degraded, "config check failed: "+reason)
			checks = append(checks, common.CheckEntry{
				CheckID: CheckConfig, Operation: CheckConfig, Outcome: graph.OutcomeFailed,
				Reason: reason, OperationKind: graph.EnumerationOperation,
				Details: map[string]any{"error": reason},
			})
		} else {
			if hasOpenWebUIHeaders(resp.Header) {
				openWebUIConfirmed = true
			}
			switch resp.StatusCode {
			case http.StatusOK:
				if resp.Truncated {
					responseTruncated = true
					degraded = append(degraded, "config response truncated at max_response_bytes")
					checks = append(checks, common.CheckEntry{
						CheckID: CheckConfig, Operation: CheckConfig, Outcome: graph.OutcomeFailed,
						Reason: "config response truncated at max_response_bytes limit", OperationKind: graph.EnumerationOperation,
						Details: map[string]any{"http_status": resp.StatusCode, "truncated": true},
					})
				} else {
					var cfgDoc configResponse
					var rawMap map[string]json.RawMessage
					if json.Unmarshal(resp.Body, &rawMap) != nil || json.Unmarshal(resp.Body, &cfgDoc) != nil || !isOpenWebUIConfig(cfgDoc, rawMap, resp.Header) {
						degraded = append(degraded, "/api/config does not identify Open WebUI")
						checks = append(checks, common.CheckEntry{
							CheckID: CheckConfig, Operation: CheckConfig, Outcome: graph.OutcomeFailed,
							Reason: "invalid JSON or non-Open WebUI response from /api/config", OperationKind: graph.EnumerationOperation,
							Details: map[string]any{"http_status": resp.StatusCode},
						})
					} else {
						openWebUIConfirmed = true
						cfgSuccess = true
						cfgBody = bytes.TrimSpace(resp.Body)
						if rawVersion == "" && strings.TrimSpace(cfgDoc.Version) != "" {
							rawVersion = common.BoundString(cfgDoc.Version, 128)
							normVersion = common.NormalizeVersion(cfgDoc.Version)
						}
						if cfgDoc.Features != nil {
							if cfgDoc.Features.Auth != nil {
								if *cfgDoc.Features.Auth {
									authAdvertised = "required"
								} else {
									authAdvertised = "none"
								}
							}
							if cfgDoc.Features.EnableSignup != nil {
								val := *cfgDoc.Features.EnableSignup
								signupEnabled = &val
							}
						}
						for _, rawList := range [][]string{cfgDoc.OllamaBaseURLs, cfgDoc.OpenAIAPIBaseURLs, cfgDoc.BackendURLs} {
							for _, rawU := range rawList {
								if ref := common.SanitizeHTTPReference(rawU); ref != "" {
									backendSet[ref] = true
								}
							}
						}
						details := map[string]any{
							"http_status":   resp.StatusCode,
							"backend_count": len(backendSet),
						}
						if authAdvertised != "" {
							details["auth_advertised"] = authAdvertised
						}
						if signupEnabled != nil {
							details["signup_enabled"] = *signupEnabled
						}
						checks = append(checks, common.CheckEntry{
							CheckID: CheckConfig, Operation: CheckConfig, Outcome: graph.OutcomeSuccess,
							Reason: "Open WebUI configuration metadata retrieved", Anonymous: true,
							OperationKind: graph.EnumerationOperation, CountForAccess: false,
							Details: details,
						})
					}
				}
			case http.StatusUnauthorized, http.StatusForbidden:
				cfgDenied = true
				if hasOpenWebUIDenial(resp.Header, resp.Body) {
					openWebUIConfirmed = true
					deniedConfirmed = true
				}
				degraded = append(degraded, fmt.Sprintf("config denied (HTTP %d)", resp.StatusCode))
				checks = append(checks, common.CheckEntry{
					CheckID: CheckConfig, Operation: CheckConfig, Outcome: graph.OutcomeDenied,
					Reason:        fmt.Sprintf("HTTP %d: authentication or authorization required", resp.StatusCode),
					OperationKind: graph.EnumerationOperation,
					Details:       map[string]any{"http_status": resp.StatusCode},
				})
			case http.StatusNotFound:
				degraded = append(degraded, "config endpoint unavailable (HTTP 404)")
				checks = append(checks, common.CheckEntry{
					CheckID: CheckConfig, Operation: CheckConfig, Outcome: graph.OutcomeFailed,
					Reason: "HTTP 404 not found (/api/config unavailable)", OperationKind: graph.EnumerationOperation,
					Details: map[string]any{"http_status": resp.StatusCode},
				})
			case http.StatusTooManyRequests:
				degraded = append(degraded, "config endpoint rate limited (HTTP 429)")
				checks = append(checks, common.CheckEntry{
					CheckID: CheckConfig, Operation: CheckConfig, Outcome: graph.OutcomeFailed,
					Reason: "HTTP 429 rate limited", OperationKind: graph.EnumerationOperation,
					Details: map[string]any{"http_status": resp.StatusCode},
				})
			default:
				degraded = append(degraded, fmt.Sprintf("config returned HTTP %d", resp.StatusCode))
				checks = append(checks, common.CheckEntry{
					CheckID: CheckConfig, Operation: CheckConfig, Outcome: graph.OutcomeFailed,
					Reason:        fmt.Sprintf("HTTP %d unexpected status", resp.StatusCode),
					OperationKind: graph.EnumerationOperation,
					Details:       map[string]any{"http_status": resp.StatusCode},
				})
			}
		}
	}

	// 3. Check: GET /api/models (enumeration check).
	{
		resp, reqErr := c.transport.Get(ctx, baseURL+"/api/models")
		common.AbsorbTransport(resp, &tlsInfo, &redirects)

		if common.IsTLSFailure(tlsInfo, c.cfg.Insecure) {
			reason := common.SanitizeError(reqErr)
			if reason == "" {
				reason = "TLS certificate verification failed: " + common.BoundString(tlsInfo.VerificationReason, 200)
			}
			checks = append(checks,
				common.CheckEntry{
					CheckID: CheckModels, Operation: CheckModels, Outcome: graph.OutcomeFailed,
					Reason: reason, OperationKind: graph.EnumerationOperation,
					Details: map[string]any{"tls_error": common.BoundString(tlsInfo.VerificationReason, 200)},
				},
				common.CheckEntry{CheckID: CheckConfigContent, Operation: CheckConfigContent, Outcome: graph.OutcomeSkipped, Reason: "prerequisite failed: TLS verification failed", OperationKind: graph.ResourceReadOperation},
			)
			return c.buildFailedResult(target, scope, vantageKey, scanID, obsTime, evID, baseURL+"/api/models", srvID, reason, checks, tlsInfo, redirects)
		}

		if reqErr != nil {
			modelsErr = reqErr
			reason := common.SanitizeError(reqErr)
			degraded = append(degraded, "models check failed: "+reason)
			checks = append(checks, common.CheckEntry{
				CheckID: CheckModels, Operation: CheckModels, Outcome: graph.OutcomeFailed,
				Reason: reason, OperationKind: graph.EnumerationOperation,
				Details: map[string]any{"error": reason},
			})
		} else {
			switch resp.StatusCode {
			case http.StatusOK:
				if resp.Truncated {
					responseTruncated = true
					degraded = append(degraded, "models response truncated at max_response_bytes")
					checks = append(checks, common.CheckEntry{
						CheckID: CheckModels, Operation: CheckModels, Outcome: graph.OutcomeFailed,
						Reason: "models response truncated at max_response_bytes limit", OperationKind: graph.EnumerationOperation,
						Details: map[string]any{"http_status": resp.StatusCode, "truncated": true},
					})
				} else {
					var mResp modelsResponse
					if err := json.Unmarshal(resp.Body, &mResp); err != nil || mResp.Data == nil {
						degraded = append(degraded, "invalid JSON response from /api/models")
						checks = append(checks, common.CheckEntry{
							CheckID: CheckModels, Operation: CheckModels, Outcome: graph.OutcomeFailed,
							Reason: "invalid JSON response from /api/models", OperationKind: graph.EnumerationOperation,
							Details: map[string]any{"http_status": resp.StatusCode},
						})
					} else {
						seen := make(map[string]bool, len(mResp.Data))
						var deduped []parsedModel
						for _, m := range mResp.Data {
							id := strings.TrimSpace(m.ID)
							if id == "" || seen[id] {
								continue
							}
							seen[id] = true
							deduped = append(deduped, parsedModel{
								ID:      id,
								Name:    common.BoundString(m.Name, 200),
								OwnedBy: common.BoundString(m.OwnedBy, 200),
							})
						}
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
							Reason: "Open WebUI models enumerated anonymously", Anonymous: true,
							OperationKind: graph.EnumerationOperation, CountForAccess: true,
							Details: map[string]any{
								"http_status": resp.StatusCode,
								"model_count": len(models),
								"truncated":   modelsTruncated,
							},
						})
					}
				}
			case http.StatusUnauthorized, http.StatusForbidden:
				modelsDenied = true
				if hasOpenWebUIDenial(resp.Header, resp.Body) {
					openWebUIConfirmed = true
					deniedConfirmed = true
				}
				degraded = append(degraded, fmt.Sprintf("models denied (HTTP %d)", resp.StatusCode))
				checks = append(checks, common.CheckEntry{
					CheckID: CheckModels, Operation: CheckModels, Outcome: graph.OutcomeDenied,
					Reason:        fmt.Sprintf("HTTP %d: authentication or authorization required", resp.StatusCode),
					OperationKind: graph.EnumerationOperation,
					Details:       map[string]any{"http_status": resp.StatusCode},
				})
			case http.StatusNotFound:
				degraded = append(degraded, "models endpoint unavailable (HTTP 404)")
				checks = append(checks, common.CheckEntry{
					CheckID: CheckModels, Operation: CheckModels, Outcome: graph.OutcomeFailed,
					Reason: "HTTP 404 not found (/api/models unavailable)", OperationKind: graph.EnumerationOperation,
					Details: map[string]any{"http_status": resp.StatusCode},
				})
			case http.StatusTooManyRequests:
				degraded = append(degraded, "models endpoint rate limited (HTTP 429)")
				checks = append(checks, common.CheckEntry{
					CheckID: CheckModels, Operation: CheckModels, Outcome: graph.OutcomeFailed,
					Reason: "HTTP 429 rate limited", OperationKind: graph.EnumerationOperation,
					Details: map[string]any{"http_status": resp.StatusCode},
				})
			default:
				degraded = append(degraded, fmt.Sprintf("models returned HTTP %d", resp.StatusCode))
				checks = append(checks, common.CheckEntry{
					CheckID: CheckModels, Operation: CheckModels, Outcome: graph.OutcomeFailed,
					Reason:        fmt.Sprintf("HTTP %d unexpected status", resp.StatusCode),
					OperationKind: graph.EnumerationOperation,
					Details:       map[string]any{"http_status": resp.StatusCode},
				})
			}
		}
	}

	// 4. Check: Bounded Configuration Content Capture (reuses /api/config body).
	var contentSummary *graph.ContentSummary
	var contentTruncated bool
	var contentTruncReasons []string
	var configCollected bool
	if !c.cfg.Content.EnabledFor(Surface) {
		checks = append(checks, common.CheckEntry{
			CheckID: CheckConfigContent, Operation: CheckConfigContent, Outcome: graph.OutcomeSkipped,
			Reason: "content collection disabled by policy", OperationKind: graph.ResourceReadOperation,
			Details: map[string]any{"skipped": true, "policy": "content_disabled"},
		})
	} else if !openWebUIConfirmed || len(cfgBody) == 0 || content.LooksBinary(cfgBody) {
		checks = append(checks, common.CheckEntry{
			CheckID: CheckConfigContent, Operation: CheckConfigContent, Outcome: graph.OutcomeSkipped,
			Reason: "prerequisite failed: /api/config body unavailable", OperationKind: graph.ResourceReadOperation,
		})
	} else {
		budget := content.NewBudget(c.cfg.Content, secrets.NewRedactor(c.cfg.Secrets))
		if ok, _ := budget.ClaimResourceItem("config"); ok {
			rec, added, addErr := budget.Add(content.RecordInput{
				DeploymentScope: scope,
				ScanID:          scanID,
				VantageKey:      vantageKey,
				ServiceID:       srvID.ID(),
				Surface:         Surface,
				CheckID:         CheckConfigContent,
				Source:          configURL,
				Kind:            content.KindConfig,
				Location:        "api/config",
				MediaType:       "application/json",
				ObservedAt:      obsTime,
				Body:            string(cfgBody),
			})
			if addErr != nil {
				return checkpoint.Result{}, fmt.Errorf("create open_webui config content record: %w", addErr)
			}
			if added {
				configCollected = true
				if c.contentSink != nil {
					if err := c.contentSink.Write(rec); err != nil {
						return checkpoint.Result{}, fmt.Errorf("write open_webui config content record: %w", err)
					}
				}
			}
		}
		contentTruncated = budget.Truncated()
		contentTruncReasons = budget.Reasons()
		cfgFlag := configCollected
		contentSummary = common.ContentSummaryFromBudget(budget, obsTime, nil, &cfgFlag)

		details := map[string]any{
			"content_items":     len(budget.Records()),
			"content_bytes":     budget.Bytes(),
			"content_truncated": contentTruncated,
		}
		if found := budget.Findings(); len(found) > 0 {
			details["detected_exposures"] = content.ExposureDetails(found)
		}
		checks = append(checks, common.CheckEntry{
			CheckID: CheckConfigContent, Operation: CheckConfigContent, Outcome: graph.OutcomeSuccess,
			Reason:        "bounded Open WebUI configuration captured into .content.jsonl",
			OperationKind: graph.ResourceReadOperation, CountForAccess: false, Details: details,
		})
	}

	var finalCoverage graph.Coverage
	var finalCoverageReason string
	var finalStatus checkpoint.TargetStatus

	allUnreachable := verErr != nil && cfgErr != nil && modelsErr != nil
	switch {
	case allUnreachable:
		finalCoverage = graph.CoverageFailed
		finalStatus = checkpoint.TargetStatusFailed
		finalCoverageReason = "target unreachable: " + common.SanitizeError(verErr)
	case !openWebUIConfirmed:
		finalCoverage = graph.CoverageFailed
		finalStatus = checkpoint.TargetStatusFailed
		finalCoverageReason = "enumeration failed: target not confirmed as Open WebUI"
	case verSuccess && cfgSuccess && modelsSuccess:
		if modelsTruncated || responseTruncated || contentTruncated {
			finalCoverage = graph.CoverageTruncated
			finalStatus = checkpoint.TargetStatusPartial
			finalCoverageReason = openWebUITruncationReason(modelsTruncated, responseTruncated, contentTruncReasons)
		} else if len(degraded) > 0 {
			finalCoverage = graph.CoveragePartial
			finalStatus = checkpoint.TargetStatusPartial
			finalCoverageReason = strings.Join(degraded, "; ")
		} else {
			finalCoverage = graph.CoverageComplete
			finalStatus = checkpoint.TargetStatusCompleted
		}
	case cfgSuccess || modelsSuccess:
		if modelsTruncated || responseTruncated || contentTruncated {
			finalCoverage = graph.CoverageTruncated
			finalStatus = checkpoint.TargetStatusPartial
			finalCoverageReason = openWebUITruncationReason(modelsTruncated, responseTruncated, contentTruncReasons)
		} else {
			finalCoverage = graph.CoveragePartial
			finalStatus = checkpoint.TargetStatusPartial
			if len(degraded) > 0 {
				finalCoverageReason = strings.Join(degraded, "; ")
			} else {
				finalCoverageReason = "partial Open WebUI metadata collected"
			}
		}
	case deniedConfirmed && (verDenied || cfgDenied || modelsDenied):
		finalCoverage = graph.CoveragePartial
		finalStatus = checkpoint.TargetStatusPartial
		finalCoverageReason = "authentication required on Open WebUI endpoint"
	default:
		finalCoverage = graph.CoverageFailed
		finalStatus = checkpoint.TargetStatusFailed
		finalCoverageReason = "enumeration failed: target not confirmed as Open WebUI"
	}

	obs := graph.Observation{
		SchemaVersion:    "1",
		ScanID:           scanID,
		CollectorVersion: "0.1.0",
		EvidenceID:       evID,
		Source:           configURL,
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
		var backendRefs []string
		for b := range backendSet {
			backendRefs = append(backendRefs, b)
		}
		sort.Strings(backendRefs)

		facts := graph.ServiceFacts{
			Endpoint:         ep,
			Name:             fmt.Sprintf("Open WebUI · %s:%d", ep.Host(), ep.Port()),
			Product:          "Open WebUI",
			Vendor:           "Open WebUI",
			VantageKey:       vantageKey,
			Access:           access,
			AuthAdvertised:   authAdvertised,
			BackendRefs:      backendRefs,
			BackendRefsBasis: graph.BasisDeclared,
			TLS:              common.TLSSummary(tlsInfo),
			Content:          contentSummary,
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
		if signupEnabled != nil {
			srvProps["signup_enabled"] = *signupEnabled
		}

		srvNode, err := graph.NewNode(srvID, obs)
		if err != nil {
			return checkpoint.Result{}, fmt.Errorf("create OpenWebUIInstance node: %w", err)
		}
		srvItem, err := emitter.NewNodeItem(srvNode, srvProps)
		if err != nil {
			return checkpoint.Result{}, fmt.Errorf("create OpenWebUIInstance node item: %w", err)
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
			if m.Name != "" {
				modelProps["display_name"] = m.Name
			}
			if m.OwnedBy != "" {
				modelProps["owned_by"] = m.OwnedBy
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

		method := CheckConfig
		confidence := "exact"
		if verSuccess {
			method = CheckVersion
		} else if !cfgSuccess {
			method = "denied_response"
			confidence = "inferred"
		}
		fpInput = &evidence.FingerprintInput{
			TargetID:           srvID.ID(),
			Product:            "Open WebUI",
			Vendor:             "Open WebUI",
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

func hasOpenWebUIHeaders(h http.Header) bool {
	s := strings.ToLower(h.Get("Server"))
	return strings.Contains(s, "open-webui") || strings.Contains(s, "open webui")
}

func hasOpenWebUIDenial(h http.Header, body []byte) bool {
	if hasOpenWebUIHeaders(h) {
		return true
	}
	b := strings.ToLower(string(body))
	www := strings.ToLower(h.Get("Www-Authenticate"))
	return strings.Contains(b, "open webui") || strings.Contains(b, "open-webui") || strings.Contains(www, "open-webui")
}

func isOpenWebUIConfig(doc configResponse, rawMap map[string]json.RawMessage, h http.Header) bool {
	if hasOpenWebUIHeaders(h) {
		return true
	}
	if strings.Contains(strings.ToLower(doc.Name), "open webui") {
		return true
	}
	if doc.Features != nil && (doc.Features.Auth != nil || doc.Features.EnableSignup != nil) {
		return true
	}
	if _, hasDefaultModels := rawMap["default_models"]; hasDefaultModels {
		if _, hasStatus := rawMap["status"]; hasStatus {
			return true
		}
	}
	if _, hasOnboarding := rawMap["onboarding"]; hasOnboarding {
		return true
	}
	return len(doc.OllamaBaseURLs) > 0 || len(doc.OpenAIAPIBaseURLs) > 0
}

func openWebUITruncationReason(modelsTruncated, responseTruncated bool, contentReasons []string) string {
	var parts []string
	if modelsTruncated {
		parts = append(parts, "model listing truncated at max_items bound")
	}
	if responseTruncated {
		parts = append(parts, "response body truncated at max_response_bytes bound")
	}
	parts = append(parts, contentReasons...)
	return strings.Join(parts, "; ")
}
