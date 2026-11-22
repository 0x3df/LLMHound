// Package litellm provides anonymous, read-only metadata enumeration of
// LiteLLM proxy gateways (/openapi.json, /v1/models, /model/info) and bounded
// configuration content capture without invoking inference or key endpoints.
package litellm

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
	// Surface is the canonical surface identifier for LiteLLM.
	Surface = "litellm"

	// DefaultPort is the default listener port for LiteLLM proxy servers.
	DefaultPort = 4000

	// Allowlisted check identifiers.
	CheckOpenAPI   = "litellm_openapi"
	CheckModels    = "litellm_models"
	CheckModelInfo = "litellm_model_info"
	CheckConfig    = "litellm_config"
)

type openAPIDoc struct {
	Info struct {
		Title   string `json:"title"`
		Version string `json:"version"`
	} `json:"info"`
	Paths map[string]json.RawMessage `json:"paths"`
}

type modelsListResponse struct {
	Object string `json:"object"`
	Data   []struct {
		ID      string `json:"id"`
		OwnedBy string `json:"owned_by,omitempty"`
		Created int64  `json:"created,omitempty"`
	} `json:"data"`
}

type modelInfoEntry struct {
	ModelName     string `json:"model_name"`
	LiteLLMParams struct {
		Model             string `json:"model"`
		APIBase           string `json:"api_base"`
		CustomLLMProvider string `json:"custom_llm_provider"`
	} `json:"litellm_params"`
	ModelInfo struct {
		ID              string `json:"id"`
		LiteLLMProvider string `json:"litellm_provider"`
	} `json:"model_info"`
}

type modelInfoResponse struct {
	Data []modelInfoEntry `json:"data"`
}

type parsedModel struct {
	ID       string
	OwnedBy  string
	Created  int64
	Provider string
	Target   string
}

// Collector implements anonymous, read-only LiteLLM enumeration.
type Collector struct {
	cfg         config.Config
	transport   *transport.Client
	contentSink content.Sink
}

// Option configures a LiteLLM Collector.
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

// New constructs a LiteLLM collector with the given configuration.
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
// configuration content capture on a LiteLLM gateway without calling inference
// or key-management endpoints.
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

	srvID, err := graph.NewServiceIdentity(scope, graph.LiteLLMGateway, ep)
	if err != nil {
		return checkpoint.Result{}, fmt.Errorf("create service identity: %w", err)
	}

	evID := common.EvidenceID(scanID, srvID.ID(), obsTime)
	baseURL := strings.TrimSuffix(ep.String(), "/")
	sourceURL := baseURL + "/openapi.json"

	var tlsInfo *transport.TLSInfo
	var redirects []transport.RedirectInfo
	var checks []common.CheckEntry
	var degraded []string

	var liteLLMConfirmed bool
	var deniedConfirmed bool
	var apiVersion string
	var rawVersion string
	var normVersion string
	var keyMgmtRoutes []string

	var openAPISuccess, openAPIDenied bool
	var openAPIErr error
	var modelsSuccess, modelsDenied bool
	var modelsErr error
	var infoSuccess, infoDenied bool
	var infoErr error

	var modelsTruncated bool
	var responseTruncated bool

	modelMap := make(map[string]parsedModel)
	var modelOrder []string
	addModel := func(m parsedModel) {
		id := strings.TrimSpace(m.ID)
		if id == "" {
			return
		}
		if existing, ok := modelMap[id]; ok {
			if existing.OwnedBy == "" {
				existing.OwnedBy = m.OwnedBy
			}
			if existing.Created == 0 {
				existing.Created = m.Created
			}
			if existing.Provider == "" {
				existing.Provider = m.Provider
			}
			if existing.Target == "" {
				existing.Target = m.Target
			}
			modelMap[id] = existing
			return
		}
		m.ID = id
		modelMap[id] = m
		modelOrder = append(modelOrder, id)
	}

	backendSet := make(map[string]bool)
	var modelInfoBody []byte
	var modelInfoURL = baseURL + "/model/info"

	// 1. Check: GET /openapi.json (metadata & route inspection only; never counts as anon_operations).
	{
		resp, reqErr := c.transport.Get(ctx, baseURL+"/openapi.json")
		common.AbsorbTransport(resp, &tlsInfo, &redirects)

		if common.IsTLSFailure(tlsInfo, c.cfg.Insecure) {
			reason := common.SanitizeError(reqErr)
			if reason == "" {
				reason = "TLS certificate verification failed: " + common.BoundString(tlsInfo.VerificationReason, 200)
			}
			checks = append(checks,
				common.CheckEntry{
					CheckID: CheckOpenAPI, Operation: CheckOpenAPI, Outcome: graph.OutcomeFailed,
					Reason: reason, OperationKind: graph.EnumerationOperation,
					Details: map[string]any{"tls_error": common.BoundString(tlsInfo.VerificationReason, 200)},
				},
				common.CheckEntry{CheckID: CheckModels, Operation: CheckModels, Outcome: graph.OutcomeSkipped, Reason: "prerequisite failed: TLS verification failed", OperationKind: graph.EnumerationOperation},
				common.CheckEntry{CheckID: CheckModelInfo, Operation: CheckModelInfo, Outcome: graph.OutcomeSkipped, Reason: "prerequisite failed: TLS verification failed", OperationKind: graph.EnumerationOperation},
				common.CheckEntry{CheckID: CheckConfig, Operation: CheckConfig, Outcome: graph.OutcomeSkipped, Reason: "prerequisite failed: TLS verification failed", OperationKind: graph.ResourceReadOperation},
			)
			return c.buildFailedResult(target, scope, vantageKey, scanID, obsTime, evID, sourceURL, srvID, reason, checks, tlsInfo, redirects)
		}

		if reqErr != nil {
			openAPIErr = reqErr
			reason := common.SanitizeError(reqErr)
			degraded = append(degraded, "openapi check failed: "+reason)
			checks = append(checks, common.CheckEntry{
				CheckID: CheckOpenAPI, Operation: CheckOpenAPI, Outcome: graph.OutcomeFailed,
				Reason: reason, OperationKind: graph.EnumerationOperation,
				Details: map[string]any{"error": reason},
			})
		} else {
			if hasLiteLLMHeaders(resp.Header) {
				liteLLMConfirmed = true
			}
			if v := extractLiteLLMVersionHeader(resp.Header); v != "" {
				rawVersion = common.BoundString(v, 128)
				normVersion = common.NormalizeVersion(v)
			}

			switch resp.StatusCode {
			case http.StatusOK:
				if resp.Truncated {
					responseTruncated = true
					degraded = append(degraded, "openapi response truncated at max_response_bytes")
					checks = append(checks, common.CheckEntry{
						CheckID: CheckOpenAPI, Operation: CheckOpenAPI, Outcome: graph.OutcomeFailed,
						Reason: "openapi response truncated at max_response_bytes limit", OperationKind: graph.EnumerationOperation,
						Details: map[string]any{"http_status": resp.StatusCode, "truncated": true},
					})
				} else {
					var doc openAPIDoc
					if err := json.Unmarshal(resp.Body, &doc); err != nil {
						degraded = append(degraded, "invalid JSON in /openapi.json")
						checks = append(checks, common.CheckEntry{
							CheckID: CheckOpenAPI, Operation: CheckOpenAPI, Outcome: graph.OutcomeFailed,
							Reason: "invalid JSON response from /openapi.json", OperationKind: graph.EnumerationOperation,
							Details: map[string]any{"http_status": resp.StatusCode},
						})
					} else if !isLiteLLMOpenAPI(doc, resp.Header) {
						degraded = append(degraded, "/openapi.json does not identify LiteLLM")
						checks = append(checks, common.CheckEntry{
							CheckID: CheckOpenAPI, Operation: CheckOpenAPI, Outcome: graph.OutcomeFailed,
							Reason: "OpenAPI document does not identify LiteLLM", OperationKind: graph.EnumerationOperation,
							Details: map[string]any{"http_status": resp.StatusCode, "title": common.BoundString(doc.Info.Title, 128)},
						})
					} else {
						liteLLMConfirmed = true
						openAPISuccess = true
						apiVersion = common.BoundString(doc.Info.Version, 128)
						keyMgmtRoutes = findKeyManagementRoutes(doc.Paths)
						details := map[string]any{
							"http_status": resp.StatusCode,
							"title":       common.BoundString(doc.Info.Title, 128),
							"api_version": apiVersion,
							"route_count": len(doc.Paths),
						}
						if len(keyMgmtRoutes) > 0 {
							details["key_management_routes"] = keyMgmtRoutes
						}
						checks = append(checks, common.CheckEntry{
							CheckID: CheckOpenAPI, Operation: CheckOpenAPI, Outcome: graph.OutcomeSuccess,
							Reason: "LiteLLM OpenAPI metadata retrieved", Anonymous: true,
							OperationKind: graph.EnumerationOperation, CountForAccess: false,
							Details: details,
						})
					}
				}
			case http.StatusUnauthorized, http.StatusForbidden:
				openAPIDenied = true
				if hasLiteLLMDenial(resp.Header, resp.Body) {
					liteLLMConfirmed = true
					deniedConfirmed = true
				}
				degraded = append(degraded, fmt.Sprintf("openapi denied (HTTP %d)", resp.StatusCode))
				checks = append(checks, common.CheckEntry{
					CheckID: CheckOpenAPI, Operation: CheckOpenAPI, Outcome: graph.OutcomeDenied,
					Reason:        fmt.Sprintf("HTTP %d: authentication or authorization required", resp.StatusCode),
					OperationKind: graph.EnumerationOperation,
					Details:       map[string]any{"http_status": resp.StatusCode},
				})
			case http.StatusNotFound:
				degraded = append(degraded, "openapi endpoint unavailable (HTTP 404)")
				checks = append(checks, common.CheckEntry{
					CheckID: CheckOpenAPI, Operation: CheckOpenAPI, Outcome: graph.OutcomeFailed,
					Reason: "HTTP 404 not found (/openapi.json unavailable)", OperationKind: graph.EnumerationOperation,
					Details: map[string]any{"http_status": resp.StatusCode},
				})
			case http.StatusTooManyRequests:
				degraded = append(degraded, "openapi endpoint rate limited (HTTP 429)")
				checks = append(checks, common.CheckEntry{
					CheckID: CheckOpenAPI, Operation: CheckOpenAPI, Outcome: graph.OutcomeFailed,
					Reason: "HTTP 429 rate limited", OperationKind: graph.EnumerationOperation,
					Details: map[string]any{"http_status": resp.StatusCode},
				})
			default:
				degraded = append(degraded, fmt.Sprintf("openapi returned HTTP %d", resp.StatusCode))
				checks = append(checks, common.CheckEntry{
					CheckID: CheckOpenAPI, Operation: CheckOpenAPI, Outcome: graph.OutcomeFailed,
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
			checks = append(checks,
				common.CheckEntry{
					CheckID: CheckModels, Operation: CheckModels, Outcome: graph.OutcomeFailed,
					Reason: reason, OperationKind: graph.EnumerationOperation,
					Details: map[string]any{"tls_error": common.BoundString(tlsInfo.VerificationReason, 200)},
				},
				common.CheckEntry{CheckID: CheckModelInfo, Operation: CheckModelInfo, Outcome: graph.OutcomeSkipped, Reason: "prerequisite failed: TLS verification failed", OperationKind: graph.EnumerationOperation},
				common.CheckEntry{CheckID: CheckConfig, Operation: CheckConfig, Outcome: graph.OutcomeSkipped, Reason: "prerequisite failed: TLS verification failed", OperationKind: graph.ResourceReadOperation},
			)
			return c.buildFailedResult(target, scope, vantageKey, scanID, obsTime, evID, baseURL+"/v1/models", srvID, reason, checks, tlsInfo, redirects)
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
			if hasLiteLLMHeaders(resp.Header) {
				liteLLMConfirmed = true
			}
			if rawVersion == "" {
				if v := extractLiteLLMVersionHeader(resp.Header); v != "" {
					rawVersion = common.BoundString(v, 128)
					normVersion = common.NormalizeVersion(v)
				}
			}
			switch resp.StatusCode {
			case http.StatusOK:
				var mResp modelsListResponse
				if resp.Truncated {
					responseTruncated = true
					degraded = append(degraded, "models response truncated at max_response_bytes")
					checks = append(checks, common.CheckEntry{
						CheckID: CheckModels, Operation: CheckModels, Outcome: graph.OutcomeFailed,
						Reason: "models response truncated at max_response_bytes limit", OperationKind: graph.EnumerationOperation,
						Details: map[string]any{"http_status": resp.StatusCode, "truncated": true},
					})
				} else if err := json.Unmarshal(resp.Body, &mResp); err != nil || mResp.Data == nil {
					degraded = append(degraded, "invalid JSON response from /v1/models")
					checks = append(checks, common.CheckEntry{
						CheckID: CheckModels, Operation: CheckModels, Outcome: graph.OutcomeFailed,
						Reason: "invalid JSON response from /v1/models", OperationKind: graph.EnumerationOperation,
						Details: map[string]any{"http_status": resp.StatusCode},
					})
				} else {
					modelsSuccess = true
					for _, m := range mResp.Data {
						addModel(parsedModel{
							ID:      m.ID,
							OwnedBy: common.BoundString(m.OwnedBy, 200),
							Created: m.Created,
						})
					}
					checks = append(checks, common.CheckEntry{
						CheckID: CheckModels, Operation: CheckModels, Outcome: graph.OutcomeSuccess,
						Reason: "models listed anonymously", Anonymous: true,
						OperationKind: graph.EnumerationOperation, CountForAccess: true,
						Details: map[string]any{"http_status": resp.StatusCode, "model_count": len(mResp.Data)},
					})
				}
			case http.StatusUnauthorized, http.StatusForbidden:
				modelsDenied = true
				if hasLiteLLMDenial(resp.Header, resp.Body) {
					liteLLMConfirmed = true
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
					Reason: "HTTP 404 not found (/v1/models unavailable)", OperationKind: graph.EnumerationOperation,
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

	// 3. Check: GET /model/info (enumeration check; also confirms LiteLLM + extracts sanitized backends).
	{
		resp, reqErr := c.transport.Get(ctx, modelInfoURL)
		common.AbsorbTransport(resp, &tlsInfo, &redirects)

		if common.IsTLSFailure(tlsInfo, c.cfg.Insecure) {
			reason := common.SanitizeError(reqErr)
			if reason == "" {
				reason = "TLS certificate verification failed: " + common.BoundString(tlsInfo.VerificationReason, 200)
			}
			checks = append(checks,
				common.CheckEntry{
					CheckID: CheckModelInfo, Operation: CheckModelInfo, Outcome: graph.OutcomeFailed,
					Reason: reason, OperationKind: graph.EnumerationOperation,
					Details: map[string]any{"tls_error": common.BoundString(tlsInfo.VerificationReason, 200)},
				},
				common.CheckEntry{CheckID: CheckConfig, Operation: CheckConfig, Outcome: graph.OutcomeSkipped, Reason: "prerequisite failed: TLS verification failed", OperationKind: graph.ResourceReadOperation},
			)
			return c.buildFailedResult(target, scope, vantageKey, scanID, obsTime, evID, modelInfoURL, srvID, reason, checks, tlsInfo, redirects)
		}

		if reqErr != nil {
			infoErr = reqErr
			reason := common.SanitizeError(reqErr)
			degraded = append(degraded, "model/info check failed: "+reason)
			checks = append(checks, common.CheckEntry{
				CheckID: CheckModelInfo, Operation: CheckModelInfo, Outcome: graph.OutcomeFailed,
				Reason: reason, OperationKind: graph.EnumerationOperation,
				Details: map[string]any{"error": reason},
			})
		} else {
			if hasLiteLLMHeaders(resp.Header) {
				liteLLMConfirmed = true
			}
			switch resp.StatusCode {
			case http.StatusOK:
				var mInfo modelInfoResponse
				if resp.Truncated {
					responseTruncated = true
					degraded = append(degraded, "model/info response truncated at max_response_bytes")
					checks = append(checks, common.CheckEntry{
						CheckID: CheckModelInfo, Operation: CheckModelInfo, Outcome: graph.OutcomeFailed,
						Reason: "model/info response truncated at max_response_bytes limit", OperationKind: graph.EnumerationOperation,
						Details: map[string]any{"http_status": resp.StatusCode, "truncated": true},
					})
				} else if err := json.Unmarshal(resp.Body, &mInfo); err != nil || mInfo.Data == nil {
					degraded = append(degraded, "invalid JSON response from /model/info")
					checks = append(checks, common.CheckEntry{
						CheckID: CheckModelInfo, Operation: CheckModelInfo, Outcome: graph.OutcomeFailed,
						Reason: "invalid JSON response from /model/info", OperationKind: graph.EnumerationOperation,
						Details: map[string]any{"http_status": resp.StatusCode},
					})
				} else {
					if hasLiteLLMModelInfoEvidence(mInfo.Data) {
						liteLLMConfirmed = true
					}
					infoSuccess = true
					modelInfoBody = bytes.TrimSpace(resp.Body)
					for _, entry := range mInfo.Data {
						provider := common.BoundString(entry.ModelInfo.LiteLLMProvider, 128)
						if provider == "" {
							provider = common.BoundString(entry.LiteLLMParams.CustomLLMProvider, 128)
						}
						if ref := common.SanitizeHTTPReference(entry.LiteLLMParams.APIBase); ref != "" {
							backendSet[ref] = true
						}
						name := strings.TrimSpace(entry.ModelName)
						if name == "" {
							name = strings.TrimSpace(entry.LiteLLMParams.Model)
						}
						addModel(parsedModel{
							ID:       name,
							Provider: provider,
							Target:   common.BoundString(entry.LiteLLMParams.Model, 256),
						})
					}
					checks = append(checks, common.CheckEntry{
						CheckID: CheckModelInfo, Operation: CheckModelInfo, Outcome: graph.OutcomeSuccess,
						Reason: "model backend metadata retrieved anonymously", Anonymous: true,
						OperationKind: graph.EnumerationOperation, CountForAccess: true,
						Details: map[string]any{
							"http_status":   resp.StatusCode,
							"entry_count":   len(mInfo.Data),
							"backend_count": len(backendSet),
						},
					})
				}
			case http.StatusUnauthorized, http.StatusForbidden:
				infoDenied = true
				if hasLiteLLMDenial(resp.Header, resp.Body) {
					liteLLMConfirmed = true
					deniedConfirmed = true
				}
				degraded = append(degraded, fmt.Sprintf("model/info denied (HTTP %d)", resp.StatusCode))
				checks = append(checks, common.CheckEntry{
					CheckID: CheckModelInfo, Operation: CheckModelInfo, Outcome: graph.OutcomeDenied,
					Reason:        fmt.Sprintf("HTTP %d: authentication or authorization required", resp.StatusCode),
					OperationKind: graph.EnumerationOperation,
					Details:       map[string]any{"http_status": resp.StatusCode},
				})
			case http.StatusNotFound:
				degraded = append(degraded, "model/info unavailable (HTTP 404)")
				checks = append(checks, common.CheckEntry{
					CheckID: CheckModelInfo, Operation: CheckModelInfo, Outcome: graph.OutcomeFailed,
					Reason: "HTTP 404 not found (/model/info unavailable)", OperationKind: graph.EnumerationOperation,
					Details: map[string]any{"http_status": resp.StatusCode},
				})
			case http.StatusTooManyRequests:
				degraded = append(degraded, "model/info rate limited (HTTP 429)")
				checks = append(checks, common.CheckEntry{
					CheckID: CheckModelInfo, Operation: CheckModelInfo, Outcome: graph.OutcomeFailed,
					Reason: "HTTP 429 rate limited", OperationKind: graph.EnumerationOperation,
					Details: map[string]any{"http_status": resp.StatusCode},
				})
			default:
				degraded = append(degraded, fmt.Sprintf("model/info returned HTTP %d", resp.StatusCode))
				checks = append(checks, common.CheckEntry{
					CheckID: CheckModelInfo, Operation: CheckModelInfo, Outcome: graph.OutcomeFailed,
					Reason:        fmt.Sprintf("HTTP %d unexpected status", resp.StatusCode),
					OperationKind: graph.EnumerationOperation,
					Details:       map[string]any{"http_status": resp.StatusCode},
				})
			}
		}
	}

	// 4. Check: Bounded Configuration Content Capture (content tier).
	var contentSummary *graph.ContentSummary
	var contentTruncated bool
	var contentTruncReasons []string
	var configCollected bool
	if !c.cfg.Content.EnabledFor(Surface) {
		checks = append(checks, common.CheckEntry{
			CheckID: CheckConfig, Operation: CheckConfig, Outcome: graph.OutcomeSkipped,
			Reason: "content collection disabled by policy", OperationKind: graph.ResourceReadOperation,
			Details: map[string]any{"skipped": true, "policy": "content_disabled"},
		})
	} else if !liteLLMConfirmed {
		checks = append(checks, common.CheckEntry{
			CheckID: CheckConfig, Operation: CheckConfig, Outcome: graph.OutcomeSkipped,
			Reason: "prerequisite failed: LiteLLM identity not established", OperationKind: graph.ResourceReadOperation,
		})
	} else {
		budget := content.NewBudget(c.cfg.Content, secrets.NewRedactor(c.cfg.Secrets))
		var cfgErrors []string
		cfgDenied := 0
		cfgAttempts := 0

		if len(modelInfoBody) > 0 && !content.LooksBinary(modelInfoBody) {
			cfgAttempts++
			if ok, _ := budget.ClaimResourceItem("model_info"); ok {
				rec, added, addErr := budget.Add(content.RecordInput{
					DeploymentScope: scope,
					ScanID:          scanID,
					VantageKey:      vantageKey,
					ServiceID:       srvID.ID(),
					Surface:         Surface,
					CheckID:         CheckConfig,
					Source:          modelInfoURL,
					Kind:            content.KindConfig,
					Location:        "model_info",
					MediaType:       "application/json",
					ObservedAt:      obsTime,
					Body:            string(modelInfoBody),
				})
				if addErr != nil {
					return checkpoint.Result{}, fmt.Errorf("create litellm model_info content record: %w", addErr)
				}
				if added {
					configCollected = true
					if c.contentSink != nil {
						if err := c.contentSink.Write(rec); err != nil {
							return checkpoint.Result{}, fmt.Errorf("write litellm model_info content record: %w", err)
						}
					}
				}
			}
		}

		// Optionally inspect GET /settings when exposed anonymously.
		settingsURL := baseURL + "/settings"
		resp, reqErr := c.transport.Get(ctx, settingsURL)
		common.AbsorbTransport(resp, &tlsInfo, &redirects)
		if reqErr == nil && resp != nil {
			switch resp.StatusCode {
			case http.StatusOK:
				trimmed := bytes.TrimSpace(resp.Body)
				if resp.Truncated {
					responseTruncated = true
					budget.MarkTruncated("settings response truncated at max_response_bytes")
					cfgErrors = append(cfgErrors, "settings: truncated at max_response_bytes")
				} else if len(trimmed) > 0 && json.Valid(trimmed) && !content.LooksBinary(trimmed) {
					cfgAttempts++
					if ok, _ := budget.ClaimResourceItem("settings"); ok {
						rec, added, addErr := budget.Add(content.RecordInput{
							DeploymentScope: scope,
							ScanID:          scanID,
							VantageKey:      vantageKey,
							ServiceID:       srvID.ID(),
							Surface:         Surface,
							CheckID:         CheckConfig,
							Source:          settingsURL,
							Kind:            content.KindConfig,
							Location:        "settings",
							MediaType:       "application/json",
							ObservedAt:      obsTime,
							Body:            string(trimmed),
						})
						if addErr != nil {
							return checkpoint.Result{}, fmt.Errorf("create litellm settings content record: %w", addErr)
						}
						if added {
							configCollected = true
							if c.contentSink != nil {
								if err := c.contentSink.Write(rec); err != nil {
									return checkpoint.Result{}, fmt.Errorf("write litellm settings content record: %w", err)
								}
							}
						}
					}
				}
			case http.StatusUnauthorized, http.StatusForbidden:
				cfgDenied++
				cfgErrors = append(cfgErrors, fmt.Sprintf("settings: HTTP %d", resp.StatusCode))
			}
		}

		contentTruncated = budget.Truncated()
		contentTruncReasons = budget.Reasons()
		if configCollected || len(budget.Findings()) > 0 || contentTruncated {
			cfgFlag := configCollected
			contentSummary = common.ContentSummaryFromBudget(budget, obsTime, nil, &cfgFlag)
		}

		switch {
		case configCollected:
			details := map[string]any{
				"content_items":     len(budget.Records()),
				"content_bytes":     budget.Bytes(),
				"content_truncated": contentTruncated,
			}
			if found := budget.Findings(); len(found) > 0 {
				details["detected_exposures"] = content.ExposureDetails(found)
			}
			checks = append(checks, common.CheckEntry{
				CheckID: CheckConfig, Operation: CheckConfig, Outcome: graph.OutcomeSuccess,
				Reason:        "bounded LiteLLM configuration captured into .content.jsonl",
				OperationKind: graph.ResourceReadOperation, CountForAccess: false, Details: details,
			})
		case cfgDenied > 0:
			checks = append(checks, common.CheckEntry{
				CheckID: CheckConfig, Operation: CheckConfig, Outcome: graph.OutcomeDenied,
				Reason:        "authentication or authorization required for LiteLLM configuration",
				OperationKind: graph.ResourceReadOperation, Details: map[string]any{"errors": cfgErrors},
			})
		case len(cfgErrors) > 0:
			checks = append(checks, common.CheckEntry{
				CheckID: CheckConfig, Operation: CheckConfig, Outcome: graph.OutcomeFailed,
				Reason:        strings.Join(cfgErrors, "; "),
				OperationKind: graph.ResourceReadOperation, Details: map[string]any{"errors": cfgErrors},
			})
		default:
			checks = append(checks, common.CheckEntry{
				CheckID: CheckConfig, Operation: CheckConfig, Outcome: graph.OutcomeSkipped,
				Reason:        "no anonymous LiteLLM configuration bodies available",
				OperationKind: graph.ResourceReadOperation,
			})
		}
	}

	// Enforce MaxItems bound on collected models.
	maxItems := c.cfg.Bounds.MaxItems
	if maxItems <= 0 {
		maxItems = 10000
	}
	if len(modelOrder) > maxItems {
		modelsTruncated = true
		modelOrder = modelOrder[:maxItems]
	}

	// Fail closed unless LiteLLM identity was established.
	var finalCoverage graph.Coverage
	var finalCoverageReason string
	var finalStatus checkpoint.TargetStatus

	allUnreachable := openAPIErr != nil && modelsErr != nil && infoErr != nil
	switch {
	case allUnreachable:
		finalCoverage = graph.CoverageFailed
		finalStatus = checkpoint.TargetStatusFailed
		finalCoverageReason = "target unreachable: " + common.SanitizeError(openAPIErr)
	case !liteLLMConfirmed:
		finalCoverage = graph.CoverageFailed
		finalStatus = checkpoint.TargetStatusFailed
		finalCoverageReason = "enumeration failed: target not confirmed as LiteLLM"
	case openAPISuccess && (modelsSuccess || infoSuccess):
		if modelsTruncated || responseTruncated || contentTruncated {
			finalCoverage = graph.CoverageTruncated
			finalStatus = checkpoint.TargetStatusPartial
			finalCoverageReason = litellmTruncationReason(modelsTruncated, responseTruncated, contentTruncReasons)
		} else if len(degraded) > 0 {
			finalCoverage = graph.CoveragePartial
			finalStatus = checkpoint.TargetStatusPartial
			finalCoverageReason = strings.Join(degraded, "; ")
		} else {
			finalCoverage = graph.CoverageComplete
			finalStatus = checkpoint.TargetStatusCompleted
		}
	case openAPISuccess || modelsSuccess || infoSuccess:
		if modelsTruncated || responseTruncated || contentTruncated {
			finalCoverage = graph.CoverageTruncated
			finalStatus = checkpoint.TargetStatusPartial
			finalCoverageReason = litellmTruncationReason(modelsTruncated, responseTruncated, contentTruncReasons)
		} else {
			finalCoverage = graph.CoveragePartial
			finalStatus = checkpoint.TargetStatusPartial
			if len(degraded) > 0 {
				finalCoverageReason = strings.Join(degraded, "; ")
			} else {
				finalCoverageReason = "partial LiteLLM metadata collected"
			}
		}
	case deniedConfirmed && (openAPIDenied || modelsDenied || infoDenied):
		finalCoverage = graph.CoveragePartial
		finalStatus = checkpoint.TargetStatusPartial
		finalCoverageReason = "authentication required on LiteLLM endpoint"
	default:
		finalCoverage = graph.CoverageFailed
		finalStatus = checkpoint.TargetStatusFailed
		finalCoverageReason = "enumeration failed: target not confirmed as LiteLLM"
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
		var backendRefs []string
		for b := range backendSet {
			backendRefs = append(backendRefs, b)
		}
		sort.Strings(backendRefs)

		facts := graph.ServiceFacts{
			Endpoint:         ep,
			Name:             fmt.Sprintf("LiteLLM · %s:%d", ep.Host(), ep.Port()),
			Product:          "LiteLLM",
			Vendor:           "BerriAI",
			VantageKey:       vantageKey,
			Access:           access,
			BackendRefs:      backendRefs,
			BackendRefsBasis: graph.BasisDeclared,
			TLS:              common.TLSSummary(tlsInfo),
			Content:          contentSummary,
		}
		if modelsSuccess || infoSuccess {
			facts.ModelCount = common.IntPtr(len(modelOrder))
		}
		srvProps := facts.Properties()
		if normVersion != "" {
			srvProps["software_version"] = normVersion
		}
		if rawVersion != "" {
			srvProps["software_version_raw"] = rawVersion
		}
		if apiVersion != "" {
			srvProps["api_version"] = apiVersion
		}
		if len(keyMgmtRoutes) > 0 {
			srvProps["key_management_routes_advertised"] = true
		}

		srvNode, err := graph.NewNode(srvID, obs)
		if err != nil {
			return checkpoint.Result{}, fmt.Errorf("create LiteLLMGateway node: %w", err)
		}
		srvItem, err := emitter.NewNodeItem(srvNode, srvProps)
		if err != nil {
			return checkpoint.Result{}, fmt.Errorf("create LiteLLMGateway node item: %w", err)
		}
		nodes = append(nodes, srvItem)

		for _, id := range modelOrder {
			m := modelMap[id]
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
			if m.OwnedBy != "" {
				modelProps["owned_by"] = m.OwnedBy
			}
			if m.Provider != "" {
				modelProps["provider"] = m.Provider
			}
			if m.Target != "" {
				modelProps["backend_model"] = m.Target
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

		method := CheckModelInfo
		confidence := "exact"
		if openAPISuccess {
			method = CheckOpenAPI
		} else if !infoSuccess {
			method = CheckModels
			confidence = "inferred"
		}
		fpInput = &evidence.FingerprintInput{
			TargetID:           srvID.ID(),
			Product:            "LiteLLM",
			Vendor:             "BerriAI",
			SoftwareVersion:    normVersion,
			SoftwareVersionRaw: rawVersion,
			APIVersion:         apiVersion,
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

func hasLiteLLMHeaders(h http.Header) bool {
	for k := range h {
		if strings.HasPrefix(strings.ToLower(k), "x-litellm-") {
			return true
		}
	}
	return strings.Contains(strings.ToLower(h.Get("Server")), "litellm")
}

func extractLiteLLMVersionHeader(h http.Header) string {
	for _, key := range []string{"X-LiteLLM-Version", "X-Litellm-Version"} {
		if v := strings.TrimSpace(h.Get(key)); v != "" {
			return v
		}
	}
	return ""
}

func isLiteLLMOpenAPI(doc openAPIDoc, h http.Header) bool {
	if strings.Contains(strings.ToLower(doc.Info.Title), "litellm") {
		return true
	}
	if hasLiteLLMHeaders(h) {
		return true
	}
	for p := range doc.Paths {
		if p == "/model/info" || p == "/key/generate" || p == "/spend/logs" {
			if _, hasModels := doc.Paths["/v1/models"]; hasModels {
				return true
			}
		}
	}
	return false
}

func hasLiteLLMDenial(h http.Header, body []byte) bool {
	if hasLiteLLMHeaders(h) {
		return true
	}
	b := strings.ToLower(string(body))
	www := strings.ToLower(h.Get("Www-Authenticate"))
	return strings.Contains(b, "litellm") || strings.Contains(www, "litellm")
}

func hasLiteLLMModelInfoEvidence(entries []modelInfoEntry) bool {
	for _, e := range entries {
		if strings.TrimSpace(e.LiteLLMParams.Model) != "" ||
			strings.TrimSpace(e.LiteLLMParams.APIBase) != "" ||
			strings.TrimSpace(e.LiteLLMParams.CustomLLMProvider) != "" ||
			strings.TrimSpace(e.ModelInfo.LiteLLMProvider) != "" {
			return true
		}
	}
	return false
}

func findKeyManagementRoutes(paths map[string]json.RawMessage) []string {
	var routes []string
	for p := range paths {
		if p == "/key/generate" || p == "/key/info" || p == "/key/list" || p == "/key/update" || p == "/key/delete" {
			routes = append(routes, p)
		}
	}
	sort.Strings(routes)
	return routes
}

func litellmTruncationReason(modelsTruncated, responseTruncated bool, contentReasons []string) string {
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
