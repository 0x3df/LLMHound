// Package langserve provides anonymous, read-only metadata enumeration of
// LangServe applications (/openapi.json, runnable route schemas, playground
// exposure) without ever calling /invoke, /batch, /stream, or /stream_log.
package langserve

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode"

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
	// Surface is the canonical surface identifier for LangServe.
	Surface = "langserve"

	// DefaultPort is the default listener port for LangServe applications.
	DefaultPort = 8000

	// Allowlisted check identifiers.
	CheckOpenAPI    = "langserve_openapi"
	CheckSchemas    = "langserve_schemas"
	CheckPlayground = "langserve_playground"
)

var runnableSuffixes = []string{
	"/invoke",
	"/batch",
	"/stream",
	"/stream_log",
	"/stream_events",
	"/input_schema",
	"/output_schema",
	"/config_schema",
	"/playground",
}

type openAPIDoc struct {
	Info struct {
		Title             string `json:"title"`
		Version           string `json:"version"`
		Description       string `json:"description,omitempty"`
		XLangServeVersion string `json:"x-langserve-version,omitempty"`
	} `json:"info"`
	Paths map[string]json.RawMessage `json:"paths"`
}

// Collector implements anonymous, read-only LangServe enumeration.
type Collector struct {
	cfg         config.Config
	transport   *transport.Client
	contentSink content.Sink
}

// Option configures a LangServe Collector.
type Option func(*Collector)

// WithTransport overrides the transport client (primarily for testing).
func WithTransport(tc *transport.Client) Option {
	return func(c *Collector) {
		c.transport = tc
	}
}

// WithContentSink configures where bounded runnable schema bodies are written.
func WithContentSink(sink content.Sink) Option {
	return func(c *Collector) {
		c.contentSink = sink
	}
}

// New constructs a LangServe collector with the given configuration.
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

// Collect performs allowlisted GET metadata checks on a LangServe target without
// invoking /invoke, /batch, /stream, or /stream_log endpoints.
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

	srvID, err := graph.NewServiceIdentity(scope, graph.LangServeApp, ep)
	if err != nil {
		return checkpoint.Result{}, fmt.Errorf("create service identity: %w", err)
	}

	evID := common.EvidenceID(scanID, srvID.ID(), obsTime)
	baseURL := strings.TrimSuffix(ep.String(), "/")
	openAPIURL := baseURL + "/openapi.json"

	var tlsInfo *transport.TLSInfo
	var redirects []transport.RedirectInfo
	var checks []common.CheckEntry
	var degraded []string

	var langServeConfirmed bool
	var deniedConfirmed bool
	var apiVersion string
	var rawVersion, normVersion string
	var openAPISuccess, openAPIDenied bool
	var openAPIErr error
	var routes []string
	var routesTruncated bool
	var responseTruncated bool
	var playgroundRoutes []string

	maxItems := c.cfg.Bounds.MaxItems
	if maxItems <= 0 {
		maxItems = 10000
	}

	// 1. Check: GET /openapi.json (enumerates runnable routes; counts as anon_operations).
	{
		resp, reqErr := c.transport.Get(ctx, openAPIURL)
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
				common.CheckEntry{CheckID: CheckSchemas, Operation: CheckSchemas, Outcome: graph.OutcomeSkipped, Reason: "prerequisite failed: TLS verification failed", OperationKind: graph.EnumerationOperation},
				common.CheckEntry{CheckID: CheckPlayground, Operation: CheckPlayground, Outcome: graph.OutcomeSkipped, Reason: "prerequisite failed: TLS verification failed", OperationKind: graph.EnumerationOperation},
			)
			return c.buildFailedResult(target, scope, vantageKey, scanID, obsTime, evID, openAPIURL, srvID, reason, checks, tlsInfo, redirects)
		}

		if reqErr != nil {
			openAPIErr = reqErr
			reason := common.SanitizeError(reqErr)
			checks = append(checks, common.CheckEntry{
				CheckID: CheckOpenAPI, Operation: CheckOpenAPI, Outcome: graph.OutcomeFailed,
				Reason: reason, OperationKind: graph.EnumerationOperation,
				Details: map[string]any{"error": reason},
			})
		} else {
			if v := extractLangServeVersionHeader(resp.Header); v != "" {
				langServeConfirmed = true
				rawVersion = common.BoundString(v, 128)
				normVersion = common.NormalizeVersion(v)
			}
			switch resp.StatusCode {
			case http.StatusOK:
				if resp.Truncated {
					responseTruncated = true
					checks = append(checks, common.CheckEntry{
						CheckID: CheckOpenAPI, Operation: CheckOpenAPI, Outcome: graph.OutcomeFailed,
						Reason: "openapi response truncated at max_response_bytes limit", OperationKind: graph.EnumerationOperation,
						Details: map[string]any{"http_status": resp.StatusCode, "truncated": true},
					})
				} else {
					var doc openAPIDoc
					if err := json.Unmarshal(resp.Body, &doc); err != nil {
						checks = append(checks, common.CheckEntry{
							CheckID: CheckOpenAPI, Operation: CheckOpenAPI, Outcome: graph.OutcomeFailed,
							Reason: "invalid JSON response from /openapi.json", OperationKind: graph.EnumerationOperation,
							Details: map[string]any{"http_status": resp.StatusCode},
						})
					} else {
						extracted, pgRoutes, isLS := extractLangServeRoutes(doc, resp.Header)
						if !isLS {
							checks = append(checks, common.CheckEntry{
								CheckID: CheckOpenAPI, Operation: CheckOpenAPI, Outcome: graph.OutcomeFailed,
								Reason: "OpenAPI document does not identify LangServe runnable endpoints", OperationKind: graph.EnumerationOperation,
								Details: map[string]any{"http_status": resp.StatusCode, "title": common.BoundString(doc.Info.Title, 128)},
							})
						} else {
							langServeConfirmed = true
							openAPISuccess = true
							apiVersion = common.BoundString(doc.Info.Version, 128)
							if rawVersion == "" && strings.TrimSpace(doc.Info.XLangServeVersion) != "" {
								rawVersion = common.BoundString(doc.Info.XLangServeVersion, 128)
								normVersion = common.NormalizeVersion(doc.Info.XLangServeVersion)
							}
							if len(extracted) > maxItems {
								routesTruncated = true
								routes = extracted[:maxItems]
							} else {
								routes = extracted
							}
							if len(pgRoutes) > maxItems {
								playgroundRoutes = pgRoutes[:maxItems]
							} else {
								playgroundRoutes = pgRoutes
							}
							checks = append(checks, common.CheckEntry{
								CheckID: CheckOpenAPI, Operation: CheckOpenAPI, Outcome: graph.OutcomeSuccess,
								Reason: "LangServe OpenAPI routes enumerated anonymously", Anonymous: true,
								OperationKind: graph.EnumerationOperation, CountForAccess: true,
								Details: map[string]any{
									"http_status":    resp.StatusCode,
									"api_version":    apiVersion,
									"runnable_count": len(routes),
									"truncated":      routesTruncated,
								},
							})
						}
					}
				}
			case http.StatusUnauthorized, http.StatusForbidden:
				openAPIDenied = true
				if hasLangServeDenial(resp.Header, resp.Body) {
					langServeConfirmed = true
					deniedConfirmed = true
				}
				checks = append(checks, common.CheckEntry{
					CheckID: CheckOpenAPI, Operation: CheckOpenAPI, Outcome: graph.OutcomeDenied,
					Reason:        fmt.Sprintf("HTTP %d: authentication or authorization required", resp.StatusCode),
					OperationKind: graph.EnumerationOperation,
					Details:       map[string]any{"http_status": resp.StatusCode},
				})
			case http.StatusNotFound:
				checks = append(checks, common.CheckEntry{
					CheckID: CheckOpenAPI, Operation: CheckOpenAPI, Outcome: graph.OutcomeFailed,
					Reason: "HTTP 404 not found (/openapi.json unavailable)", OperationKind: graph.EnumerationOperation,
					Details: map[string]any{"http_status": resp.StatusCode},
				})
			case http.StatusTooManyRequests:
				checks = append(checks, common.CheckEntry{
					CheckID: CheckOpenAPI, Operation: CheckOpenAPI, Outcome: graph.OutcomeFailed,
					Reason: "HTTP 429 rate limited", OperationKind: graph.EnumerationOperation,
					Details: map[string]any{"http_status": resp.StatusCode},
				})
			default:
				checks = append(checks, common.CheckEntry{
					CheckID: CheckOpenAPI, Operation: CheckOpenAPI, Outcome: graph.OutcomeFailed,
					Reason:        fmt.Sprintf("HTTP %d unexpected status", resp.StatusCode),
					OperationKind: graph.EnumerationOperation,
					Details:       map[string]any{"http_status": resp.StatusCode},
				})
			}
		}
	}

	// 2. Check: GET <route>/{input_schema,output_schema,config_schema} (+ optional content capture).
	var contentSummary *graph.ContentSummary
	var contentTruncated bool
	var contentTruncReasons []string
	schemasSuccess := 0
	schemasDenied := 0
	schemaAttempts := 0
	if !openAPISuccess {
		checks = append(checks, common.CheckEntry{
			CheckID: CheckSchemas, Operation: CheckSchemas, Outcome: graph.OutcomeSkipped,
			Reason: "prerequisite failed: OpenAPI routes unavailable", OperationKind: graph.EnumerationOperation,
		})
	} else if len(routes) == 0 {
		checks = append(checks, common.CheckEntry{
			CheckID: CheckSchemas, Operation: CheckSchemas, Outcome: graph.OutcomeSkipped,
			Reason: "no runnable routes available to inspect", OperationKind: graph.EnumerationOperation,
		})
	} else {
		var budget *content.Budget
		if c.cfg.Content.EnabledFor(Surface) {
			budget = content.NewBudget(c.cfg.Content, secrets.NewRedactor(c.cfg.Secrets))
		}
		var schemaErrors []string
		configCollected := false

		for _, route := range routes {
			prefix := strings.TrimRight(route, "/")
			for _, suffix := range []string{"/input_schema", "/output_schema", "/config_schema"} {
				sURL, ok := buildScopedRouteURL(baseURL, prefix+suffix)
				if !ok {
					continue
				}
				schemaAttempts++
				resp, reqErr := c.transport.Get(ctx, sURL)
				common.AbsorbTransport(resp, &tlsInfo, &redirects)
				if reqErr != nil {
					schemaErrors = append(schemaErrors, fmt.Sprintf("%s%s: %s", route, suffix, common.SanitizeError(reqErr)))
					continue
				}
				switch resp.StatusCode {
				case http.StatusOK:
					if resp.Truncated {
						responseTruncated = true
						if budget != nil {
							budget.MarkTruncated(fmt.Sprintf("schema %s%s truncated at max_response_bytes", route, suffix))
						}
						schemaErrors = append(schemaErrors, fmt.Sprintf("%s%s: truncated at max_response_bytes", route, suffix))
						continue
					}
					trimmed := bytes.TrimSpace(resp.Body)
					if len(trimmed) == 0 || !json.Valid(trimmed) {
						schemaErrors = append(schemaErrors, fmt.Sprintf("%s%s: invalid JSON schema", route, suffix))
						continue
					}
					schemasSuccess++
					if budget != nil && !content.LooksBinary(trimmed) {
						if ok, _ := budget.ClaimResourceItem(route); ok {
							rec, added, addErr := budget.Add(content.RecordInput{
								DeploymentScope: scope,
								ScanID:          scanID,
								VantageKey:      vantageKey,
								ServiceID:       srvID.ID(),
								Surface:         Surface,
								CheckID:         CheckSchemas,
								Source:          sURL,
								Kind:            content.KindConfig,
								Location:        route + suffix,
								MediaType:       "application/json",
								ObservedAt:      obsTime,
								Body:            string(trimmed),
							})
							if addErr != nil {
								return checkpoint.Result{}, fmt.Errorf("create langserve schema content record: %w", addErr)
							}
							if added {
								configCollected = true
								if c.contentSink != nil {
									if err := c.contentSink.Write(rec); err != nil {
										return checkpoint.Result{}, fmt.Errorf("write langserve schema content record: %w", err)
									}
								}
							}
						}
					}
				case http.StatusUnauthorized, http.StatusForbidden:
					schemasDenied++
					schemaErrors = append(schemaErrors, fmt.Sprintf("%s%s: HTTP %d", route, suffix, resp.StatusCode))
				default:
					schemaErrors = append(schemaErrors, fmt.Sprintf("%s%s: HTTP %d", route, suffix, resp.StatusCode))
				}
			}
		}

		if budget != nil {
			contentTruncated = budget.Truncated()
			contentTruncReasons = budget.Reasons()
			cfgFlag := configCollected
			contentSummary = common.ContentSummaryFromBudget(budget, obsTime, nil, &cfgFlag)
		}

		switch {
		case schemasSuccess > 0:
			details := map[string]any{
				"schemas_retrieved": schemasSuccess,
				"schemas_attempted": schemaAttempts,
			}
			if budget != nil {
				details["content_items"] = len(budget.Records())
				details["content_bytes"] = budget.Bytes()
				details["content_truncated"] = contentTruncated
				if found := budget.Findings(); len(found) > 0 {
					details["detected_exposures"] = content.ExposureDetails(found)
				}
			}
			if len(schemaErrors) > 0 {
				details["errors"] = schemaErrors
			}
			checks = append(checks, common.CheckEntry{
				CheckID: CheckSchemas, Operation: CheckSchemas, Outcome: graph.OutcomeSuccess,
				Reason:        fmt.Sprintf("LangServe runnable schemas retrieved (%d of %d)", schemasSuccess, schemaAttempts),
				Anonymous:     true,
				OperationKind: graph.EnumerationOperation, CountForAccess: true, Details: details,
			})
		case schemasDenied > 0 && schemasDenied == schemaAttempts:
			degraded = append(degraded, "runnable schemas denied")
			checks = append(checks, common.CheckEntry{
				CheckID: CheckSchemas, Operation: CheckSchemas, Outcome: graph.OutcomeDenied,
				Reason: "authentication or authorization required for runnable schemas", OperationKind: graph.EnumerationOperation,
				Details: map[string]any{"errors": schemaErrors},
			})
		default:
			degraded = append(degraded, "runnable schema retrieval failed")
			checks = append(checks, common.CheckEntry{
				CheckID: CheckSchemas, Operation: CheckSchemas, Outcome: graph.OutcomeFailed,
				Reason: "failed to retrieve runnable schemas: " + strings.Join(schemaErrors, "; "), OperationKind: graph.EnumerationOperation,
				Details: map[string]any{"errors": schemaErrors},
			})
		}
	}

	// 3. Check: GET <route>/playground/ (exposure check).
	var playgroundExposed *bool
	if !openAPISuccess {
		checks = append(checks, common.CheckEntry{
			CheckID: CheckPlayground, Operation: CheckPlayground, Outcome: graph.OutcomeSkipped,
			Reason: "prerequisite failed: OpenAPI routes unavailable", OperationKind: graph.EnumerationOperation,
		})
	} else if len(playgroundRoutes) == 0 {
		checks = append(checks, common.CheckEntry{
			CheckID: CheckPlayground, Operation: CheckPlayground, Outcome: graph.OutcomeSkipped,
			Reason: "no playground routes listed in OpenAPI", OperationKind: graph.EnumerationOperation,
		})
	} else {
		pgSuccess := 0
		pgDenied := 0
		var pgErrors []string
		for _, rPath := range playgroundRoutes {
			pgURL, ok := buildScopedRouteURL(baseURL, rPath+"/playground/")
			if !ok {
				continue
			}
			resp, reqErr := c.transport.Get(ctx, pgURL)
			common.AbsorbTransport(resp, &tlsInfo, &redirects)
			if reqErr != nil {
				pgErrors = append(pgErrors, fmt.Sprintf("%s: %s", rPath, common.SanitizeError(reqErr)))
				continue
			}
			switch resp.StatusCode {
			case http.StatusOK:
				bodyLower := strings.ToLower(string(resp.Body))
				if strings.Contains(bodyLower, "type=\"password\"") || strings.Contains(bodyLower, "sign in") {
					pgDenied++
					pgErrors = append(pgErrors, fmt.Sprintf("%s: login page", rPath))
					continue
				}
				pgSuccess++
			case http.StatusUnauthorized, http.StatusForbidden:
				pgDenied++
				pgErrors = append(pgErrors, fmt.Sprintf("%s: HTTP %d", rPath, resp.StatusCode))
			default:
				pgErrors = append(pgErrors, fmt.Sprintf("%s: HTTP %d", rPath, resp.StatusCode))
			}
		}

		switch {
		case pgSuccess > 0:
			tVal := true
			playgroundExposed = &tVal
			checks = append(checks, common.CheckEntry{
				CheckID: CheckPlayground, Operation: CheckPlayground, Outcome: graph.OutcomeSuccess,
				Reason:        fmt.Sprintf("LangServe playground reachable anonymously (%d routes)", pgSuccess),
				Anonymous:     true,
				OperationKind: graph.EnumerationOperation, CountForAccess: true,
				Details: map[string]any{"exposed_count": pgSuccess},
			})
		case pgDenied > 0 && pgDenied == len(playgroundRoutes):
			fVal := false
			playgroundExposed = &fVal
			degraded = append(degraded, "playground access denied")
			checks = append(checks, common.CheckEntry{
				CheckID: CheckPlayground, Operation: CheckPlayground, Outcome: graph.OutcomeDenied,
				Reason: "authentication required for playground", OperationKind: graph.EnumerationOperation,
				Details: map[string]any{"errors": pgErrors},
			})
		default:
			degraded = append(degraded, "playground check failed")
			checks = append(checks, common.CheckEntry{
				CheckID: CheckPlayground, Operation: CheckPlayground, Outcome: graph.OutcomeFailed,
				Reason: "failed to inspect playground: " + strings.Join(pgErrors, "; "), OperationKind: graph.EnumerationOperation,
				Details: map[string]any{"errors": pgErrors},
			})
		}
	}

	var finalCoverage graph.Coverage
	var finalCoverageReason string
	var finalStatus checkpoint.TargetStatus

	switch {
	case openAPIErr != nil && !langServeConfirmed:
		finalCoverage = graph.CoverageFailed
		finalStatus = checkpoint.TargetStatusFailed
		finalCoverageReason = "target unreachable: " + common.SanitizeError(openAPIErr)
	case !langServeConfirmed:
		finalCoverage = graph.CoverageFailed
		finalStatus = checkpoint.TargetStatusFailed
		finalCoverageReason = "enumeration failed: target not confirmed as LangServe"
	case openAPISuccess:
		if routesTruncated || responseTruncated || contentTruncated {
			finalCoverage = graph.CoverageTruncated
			finalStatus = checkpoint.TargetStatusPartial
			finalCoverageReason = langServeTruncationReason(routesTruncated, responseTruncated, contentTruncReasons)
		} else if len(degraded) > 0 {
			finalCoverage = graph.CoveragePartial
			finalStatus = checkpoint.TargetStatusPartial
			finalCoverageReason = strings.Join(degraded, "; ")
		} else {
			finalCoverage = graph.CoverageComplete
			finalStatus = checkpoint.TargetStatusCompleted
		}
	case deniedConfirmed && openAPIDenied:
		finalCoverage = graph.CoveragePartial
		finalStatus = checkpoint.TargetStatusPartial
		finalCoverageReason = "authentication required on LangServe endpoint"
	default:
		finalCoverage = graph.CoverageFailed
		finalStatus = checkpoint.TargetStatusFailed
		finalCoverageReason = "enumeration failed: target not confirmed as LangServe"
	}

	obs := graph.Observation{
		SchemaVersion:    "1",
		ScanID:           scanID,
		CollectorVersion: "0.1.0",
		EvidenceID:       evID,
		Source:           openAPIURL,
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
			Name:       fmt.Sprintf("LangServe · %s:%d", ep.Host(), ep.Port()),
			Product:    "LangServe",
			Vendor:     "LangChain",
			VantageKey: vantageKey,
			Access:     access,
			TLS:        common.TLSSummary(tlsInfo),
			Content:    contentSummary,
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
		if openAPISuccess {
			srvProps["runnable_count"] = len(routes)
			if len(routes) > 0 {
				srvProps["runnable_routes"] = routes
			}
		}
		if playgroundExposed != nil {
			srvProps["playground_exposed"] = *playgroundExposed
		}

		srvNode, err := graph.NewNode(srvID, obs)
		if err != nil {
			return checkpoint.Result{}, fmt.Errorf("create LangServeApp node: %w", err)
		}
		srvItem, err := emitter.NewNodeItem(srvNode, srvProps)
		if err != nil {
			return checkpoint.Result{}, fmt.Errorf("create LangServeApp node item: %w", err)
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

		method := CheckOpenAPI
		confidence := "exact"
		if !openAPISuccess {
			method = "denied_response"
			confidence = "inferred"
		}
		fpInput = &evidence.FingerprintInput{
			TargetID:           srvID.ID(),
			Product:            "LangServe",
			Vendor:             "LangChain",
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

func extractLangServeVersionHeader(h http.Header) string {
	for _, key := range []string{"X-LangServe-Version", "X-Langserve-Version"} {
		if v := strings.TrimSpace(h.Get(key)); v != "" {
			return v
		}
	}
	return ""
}

func hasLangServeDenial(h http.Header, body []byte) bool {
	if extractLangServeVersionHeader(h) != "" {
		return true
	}
	b := strings.ToLower(string(body))
	www := strings.ToLower(h.Get("Www-Authenticate"))
	return strings.Contains(b, "langserve") || strings.Contains(www, "langserve")
}

func isSafeLangServeRoute(route string) bool {
	if route == "" || !strings.HasPrefix(route, "/") || strings.HasPrefix(route, "//") {
		return false
	}
	if strings.ContainsAny(route, "@?#\\") || strings.Contains(route, "..") {
		return false
	}
	for _, r := range route {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func buildScopedRouteURL(baseURL, relPath string) (string, bool) {
	if !isSafeLangServeRoute(relPath) {
		return "", false
	}
	baseParsed, err := url.Parse(baseURL)
	if err != nil {
		return "", false
	}
	joined, err := url.Parse(baseURL + relPath)
	if err != nil || joined.User != nil {
		return "", false
	}
	if !strings.EqualFold(joined.Scheme, baseParsed.Scheme) || !strings.EqualFold(joined.Host, baseParsed.Host) {
		return "", false
	}
	return joined.String(), true
}

func extractLangServeRoutes(doc openAPIDoc, h http.Header) (routes []string, playgroundRoutes []string, confirmed bool) {
	suffixCountByBase := make(map[string]map[string]bool)
	hasPlayground := make(map[string]bool)

	for p := range doc.Paths {
		if !isSafeLangServeRoute(p) {
			continue
		}
		clean := strings.TrimRight(p, "/")
		for _, suffix := range runnableSuffixes {
			if strings.HasSuffix(clean, suffix) {
				base := strings.TrimSuffix(clean, suffix)
				if base == "" {
					base = ""
				} else if !isSafeLangServeRoute(base) {
					continue
				}
				if suffixCountByBase[base] == nil {
					suffixCountByBase[base] = make(map[string]bool)
				}
				suffixCountByBase[base][suffix] = true
				if suffix == "/playground" {
					hasPlayground[base] = true
				}
				break
			}
		}
	}

	var bases []string
	for base, suffixes := range suffixCountByBase {
		hasInvokeOrStream := suffixes["/invoke"] || suffixes["/batch"] || suffixes["/stream"] || suffixes["/stream_log"] || suffixes["/stream_events"]
		hasSchemaOrPlayground := suffixes["/input_schema"] || suffixes["/output_schema"] || suffixes["/config_schema"] || suffixes["/playground"]
		if (hasInvokeOrStream && hasSchemaOrPlayground) || len(suffixes) >= 3 {
			confirmed = true
			if base == "" {
				bases = append(bases, "/")
			} else {
				bases = append(bases, base)
			}
			if hasPlayground[base] {
				playgroundRoutes = append(playgroundRoutes, base)
			}
		}
	}

	if extractLangServeVersionHeader(h) != "" ||
		strings.Contains(strings.ToLower(doc.Info.Title), "langserve") ||
		strings.Contains(strings.ToLower(doc.Info.Description), "langserve") ||
		doc.Info.XLangServeVersion != "" {
		confirmed = true
	}

	sort.Strings(bases)
	sort.Strings(playgroundRoutes)
	return bases, playgroundRoutes, confirmed
}

func langServeTruncationReason(routesTruncated, responseTruncated bool, contentReasons []string) string {
	var parts []string
	if routesTruncated {
		parts = append(parts, "runnable route listing truncated at max_items bound")
	}
	if responseTruncated {
		parts = append(parts, "response body truncated at max_response_bytes bound")
	}
	parts = append(parts, contentReasons...)
	return strings.Join(parts, "; ")
}
