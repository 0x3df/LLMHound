// Package ollama provides anonymous, read-only collection of Ollama LLM inference servers.
// It verifies documented version and model metadata endpoints (/api/version, /api/tags, /api/ps),
// records honest outcomes, reasons, and coverage, records model provenance, enforces size limits,
// requires explicit opt-in for sensitive modelfiles/prompts (/api/show), and strictly forbids
// any generation or mutation operations.
package ollama

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/0x3df/LLMHound/internal/checkpoint"
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
	// Surface is the canonical surface identifier for Ollama.
	Surface = "ollama"

	// DefaultPort is the standard Ollama listener port.
	DefaultPort = 11434

	// Allowlisted check identifiers
	CheckVersion = "ollama_version"
	CheckTags    = "ollama_tags"
	CheckPS      = "ollama_ps"
	CheckShow    = "ollama_show"
)

// VersionResponse represents the payload returned by GET /api/version.
type VersionResponse struct {
	Version string `json:"version"`
}

// ModelDetails contains architecture, quantization, and family metadata.
type ModelDetails struct {
	ParentModel       string   `json:"parent_model,omitempty"`
	Format            string   `json:"format,omitempty"`
	Family            string   `json:"family,omitempty"`
	Families          []string `json:"families,omitempty"`
	ParameterSize     string   `json:"parameter_size,omitempty"`
	QuantizationLevel string   `json:"quantization_level,omitempty"`
}

// ModelInfo describes a single model from GET /api/tags or GET /api/ps.
type ModelInfo struct {
	Name       string       `json:"name"`
	Model      string       `json:"model,omitempty"`
	ModifiedAt string       `json:"modified_at,omitempty"`
	Size       int64        `json:"size,omitempty"`
	Digest     string       `json:"digest,omitempty"`
	Details    ModelDetails `json:"details,omitempty"`
	ExpiresAt  string       `json:"expires_at,omitempty"`
	SizeVRAM   int64        `json:"size_vram,omitempty"`
}

// TagsResponse represents the payload returned by GET /api/tags.
type TagsResponse struct {
	Models []ModelInfo `json:"models"`
}

// PSResponse represents the payload returned by GET /api/ps.
type PSResponse struct {
	Models []ModelInfo `json:"models"`
}

// ShowRequest defines parameters for POST /api/show.
type ShowRequest struct {
	Name string `json:"name"`
}

// ShowProvenance holds the redacted non-content provenance from POST /api/show.
type ShowProvenance struct {
	Details ModelDetails `json:"details,omitempty"`
	License string       `json:"license,omitempty"`
}

// ShowResponse decodes POST /api/show. Content fields (modelfile, template,
// system, parameters) are written only to the restricted .content.jsonl sink
// under configured bounds and never copied into graph nodes or evidence.
type ShowResponse struct {
	Details    ModelDetails `json:"details,omitempty"`
	License    string       `json:"license,omitempty"`
	Modelfile  string       `json:"modelfile,omitempty"`
	Parameters string       `json:"parameters,omitempty"`
	Template   string       `json:"template,omitempty"`
	System     string       `json:"system,omitempty"`
}

const maxProvenanceFieldLen = 200

// Collector implements Ollama surface enumeration.
type Collector struct {
	cfg         config.Config
	transport   *transport.Client
	contentSink content.Sink
}

// Option configures Collector behavior.
type Option func(*Collector)

// WithTransport sets a custom transport client.
func WithTransport(tc *transport.Client) Option {
	return func(c *Collector) {
		c.transport = tc
	}
}

// WithContentSink configures where bounded content-tier records are written.
func WithContentSink(sink content.Sink) Option {
	return func(c *Collector) {
		c.contentSink = sink
	}
}

// New constructs an Ollama collector with the given configuration.
func New(cfg config.Config, opts ...Option) *Collector {
	c := &Collector{
		cfg: cfg,
		transport: transport.NewClient(transport.Config{
			Bounds:          cfg.Bounds,
			Insecure:        cfg.Insecure,
			UserAgent:       cfg.UserAgent,
			AuthorizedHosts: cfg.Targets,
		}),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// ParseTargetEndpoint normalizes an input target string into a canonical graph.Endpoint.
func ParseTargetEndpoint(targetStr string) (graph.Endpoint, string, error) {
	trimmed := strings.TrimSpace(targetStr)
	if trimmed == "" {
		return graph.Endpoint{}, "", errors.New("empty target")
	}

	rawURL := trimmed
	if !strings.Contains(rawURL, "://") {
		hostPart := rawURL
		if _, err := netip.ParseAddr(hostPart); err == nil {
			rawURL = "http://" + net.JoinHostPort(hostPart, strconv.Itoa(DefaultPort))
		} else if _, _, err := net.SplitHostPort(hostPart); err != nil {
			rawURL = fmt.Sprintf("http://%s:%d", hostPart, DefaultPort)
		} else {
			rawURL = "http://" + hostPart
		}
	}

	ep, err := graph.ParseEndpoint(rawURL, "")
	if err != nil {
		return graph.Endpoint{}, "", fmt.Errorf("parse target endpoint %q: %w", targetStr, err)
	}
	return ep, ep.Host(), nil
}

// Collect executes allowlisted Ollama checks against the target.
func (c *Collector) Collect(
	ctx context.Context,
	target string,
	scope string,
	vantageKey string,
	scanID string,
	obsTime time.Time,
	resolver *correlate.Resolver,
) (checkpoint.Result, error) {
	if strings.TrimSpace(scope) == "" || strings.TrimSpace(vantageKey) == "" {
		return checkpoint.Result{}, errors.New("collection requires a deployment scope and vantage key")
	}

	ep, targetHost, err := ParseTargetEndpoint(target)
	if err != nil {
		return checkpoint.Result{}, err
	}

	srvID, err := graph.NewServiceIdentity(scope, graph.OllamaInstance, ep)
	if err != nil {
		return checkpoint.Result{}, fmt.Errorf("create service identity: %w", err)
	}

	evidenceID := generateEvidenceID(scanID, srvID.ID(), obsTime)
	baseURL := strings.TrimSuffix(ep.String(), "/")
	sourceURL := baseURL + "/api/tags"

	// Intermediate storage for checks, nodes, edges, and evidence
	var checkResults []graph.CheckResult
	var checkDetails = make(map[string]map[string]any)
	var accessEv *graph.AccessEvidence
	var fpInput *evidence.FingerprintInput
	var tlsInfo *transport.TLSInfo
	var redirects []transport.RedirectInfo

	var reportedVersion string
	var rawReportedVersion string
	var catalogModels []ModelInfo
	var catalogTruncated bool
	var psTruncated bool
	var runningModels []ModelInfo
	var degraded []string
	absorb := func(resp *transport.Response) {
		if resp == nil {
			return
		}
		if resp.TLS != nil && tlsInfo == nil {
			tlsInfo = resp.TLS
		}
		redirects = append(redirects, resp.Redirects...)
	}
	var responseTruncated bool
	provenance := make(map[string]ShowProvenance)

	var versionCheckErr error
	var tagsCheckErr error
	var totalTransportFailures int
	var totalDeniedCount int

	// 1. Check: Runtime Version (GET /api/version)
	{
		checkID := CheckVersion
		op := "ollama_version"
		verURL := baseURL + "/api/version"
		resp, reqErr := c.transport.Get(ctx, verURL)
		absorb(resp)

		if reqErr != nil {
			versionCheckErr = reqErr
			totalTransportFailures++
			reason := sanitizeError(reqErr)
			checkResults = append(checkResults, graph.CheckResult{
				CheckID:   checkID,
				Operation: op,
				TargetID:  srvID.ID(),
				Outcome:   graph.OutcomeFailed,
				Reason:    reason,
			})
			checkDetails[checkID] = map[string]any{"error": reason}
		} else {
			switch resp.StatusCode {
			case http.StatusOK:
				var v VersionResponse
				if err := json.Unmarshal(resp.Body, &v); err != nil || strings.TrimSpace(v.Version) == "" {
					checkResults = append(checkResults, graph.CheckResult{
						CheckID:   checkID,
						Operation: op,
						TargetID:  srvID.ID(),
						Outcome:   graph.OutcomeFailed,
						Reason:    "invalid JSON or missing version in response",
					})
					checkDetails[checkID] = map[string]any{"http_status": resp.StatusCode}
				} else {
					rawReportedVersion = strings.TrimSpace(v.Version)
					reportedVersion = normalizeVersion(rawReportedVersion)
					checkResults = append(checkResults, graph.CheckResult{
						CheckID:   checkID,
						Operation: op,
						TargetID:  srvID.ID(),
						Outcome:   graph.OutcomeSuccess,
						Reason:    fmt.Sprintf("runtime version reported: %s", rawReportedVersion),
					})
					checkDetails[checkID] = map[string]any{
						"http_status":          resp.StatusCode,
						"version":              reportedVersion,
						"software_version_raw": rawReportedVersion,
					}

					fpInput = &evidence.FingerprintInput{
						TargetID:           srvID.ID(),
						Product:            "Ollama",
						Vendor:             "Ollama",
						SoftwareVersion:    reportedVersion,
						SoftwareVersionRaw: rawReportedVersion,
						Method:             "api_version",
						Confidence:         "exact",
						Details: map[string]any{
							"http_status": resp.StatusCode,
						},
					}
				}
			case http.StatusUnauthorized, http.StatusForbidden:
				totalDeniedCount++
				checkResults = append(checkResults, graph.CheckResult{
					CheckID:   checkID,
					Operation: op,
					TargetID:  srvID.ID(),
					Outcome:   graph.OutcomeDenied,
					Reason:    fmt.Sprintf("HTTP %d: authentication or authorization required", resp.StatusCode),
				})
				checkDetails[checkID] = map[string]any{"http_status": resp.StatusCode}
			case http.StatusNotFound:
				checkResults = append(checkResults, graph.CheckResult{
					CheckID:   checkID,
					Operation: op,
					TargetID:  srvID.ID(),
					Outcome:   graph.OutcomeFailed,
					Reason:    "HTTP 404 not found (version endpoint unavailable)",
				})
				checkDetails[checkID] = map[string]any{"http_status": resp.StatusCode}
			default:
				checkResults = append(checkResults, graph.CheckResult{
					CheckID:   checkID,
					Operation: op,
					TargetID:  srvID.ID(),
					Outcome:   graph.OutcomeFailed,
					Reason:    fmt.Sprintf("HTTP %d unexpected status", resp.StatusCode),
				})
				checkDetails[checkID] = map[string]any{"http_status": resp.StatusCode}
			}
		}
	}

	// 2. Check: Model Catalog (GET /api/tags)
	{
		checkID := CheckTags
		op := "ollama_tags"
		tagsURL := baseURL + "/api/tags"
		resp, reqErr := c.transport.Get(ctx, tagsURL)
		absorb(resp)

		if reqErr != nil {
			tagsCheckErr = reqErr
			totalTransportFailures++
			reason := sanitizeError(reqErr)
			checkResults = append(checkResults, graph.CheckResult{
				CheckID:   checkID,
				Operation: op,
				TargetID:  srvID.ID(),
				Outcome:   graph.OutcomeFailed,
				Reason:    reason,
			})
			checkDetails[checkID] = map[string]any{"error": reason}
		} else {
			switch resp.StatusCode {
			case http.StatusOK:
				var t TagsResponse
				if err := json.Unmarshal(resp.Body, &t); err != nil {
					reason := "invalid JSON response from tags endpoint"
					if resp.Truncated {
						responseTruncated = true
						reason = "tags response truncated at max_response_bytes limit"
					}
					checkResults = append(checkResults, graph.CheckResult{
						CheckID:   checkID,
						Operation: op,
						TargetID:  srvID.ID(),
						Outcome:   graph.OutcomeFailed,
						Reason:    reason,
					})
					checkDetails[checkID] = map[string]any{"http_status": resp.StatusCode, "truncated": resp.Truncated}
				} else {
					checkResults = append(checkResults, graph.CheckResult{
						CheckID:   checkID,
						Operation: op,
						TargetID:  srvID.ID(),
						Outcome:   graph.OutcomeSuccess,
						Reason:    "tags listed anonymously",
					})
					checkDetails[checkID] = map[string]any{
						"http_status": resp.StatusCode,
						"model_count": len(t.Models),
					}

					// Valid anonymous enumeration access evidence
					accessEv = &graph.AccessEvidence{
						CheckID:       checkID,
						Operation:     op,
						TargetID:      srvID.ID(),
						Outcome:       graph.OutcomeSuccess,
						Reason:        "tags listed anonymously",
						Anonymous:     true,
						OperationKind: graph.EnumerationOperation,
					}

					// Apply MaxItems bounding
					maxItems := c.cfg.Bounds.MaxItems
					if maxItems <= 0 {
						maxItems = 10000
					}
					if len(t.Models) > maxItems {
						catalogTruncated = true
						catalogModels = t.Models[:maxItems]
					} else {
						catalogModels = t.Models
					}
				}
			case http.StatusUnauthorized, http.StatusForbidden:
				totalDeniedCount++
				checkResults = append(checkResults, graph.CheckResult{
					CheckID:   checkID,
					Operation: op,
					TargetID:  srvID.ID(),
					Outcome:   graph.OutcomeDenied,
					Reason:    fmt.Sprintf("HTTP %d: authentication or authorization required", resp.StatusCode),
				})
				checkDetails[checkID] = map[string]any{"http_status": resp.StatusCode}
			case http.StatusNotFound:
				checkResults = append(checkResults, graph.CheckResult{
					CheckID:   checkID,
					Operation: op,
					TargetID:  srvID.ID(),
					Outcome:   graph.OutcomeFailed,
					Reason:    "HTTP 404 not found (tags endpoint unavailable)",
				})
				checkDetails[checkID] = map[string]any{"http_status": resp.StatusCode}
			default:
				checkResults = append(checkResults, graph.CheckResult{
					CheckID:   checkID,
					Operation: op,
					TargetID:  srvID.ID(),
					Outcome:   graph.OutcomeFailed,
					Reason:    fmt.Sprintf("HTTP %d unexpected status", resp.StatusCode),
				})
				checkDetails[checkID] = map[string]any{"http_status": resp.StatusCode}
			}
		}
	}

	// 3. Check: Running Models (GET /api/ps)
	{
		checkID := CheckPS
		op := "ollama_ps"
		psURL := baseURL + "/api/ps"
		resp, reqErr := c.transport.Get(ctx, psURL)
		absorb(resp)

		if reqErr != nil {
			reason := sanitizeError(reqErr)
			checkResults = append(checkResults, graph.CheckResult{
				CheckID:   checkID,
				Operation: op,
				TargetID:  srvID.ID(),
				Outcome:   graph.OutcomeFailed,
				Reason:    reason,
			})
			checkDetails[checkID] = map[string]any{"error": reason}
			degraded = append(degraded, "running models check failed: "+reason)
		} else {
			switch resp.StatusCode {
			case http.StatusOK:
				var ps PSResponse
				if err := json.Unmarshal(resp.Body, &ps); err == nil {
					runningModels = ps.Models
					if maxItems := c.cfg.Bounds.MaxItems; maxItems > 0 && len(runningModels) > maxItems {
						psTruncated = true
						runningModels = runningModels[:maxItems]
					}
					checkResults = append(checkResults, graph.CheckResult{
						CheckID:   checkID,
						Operation: op,
						TargetID:  srvID.ID(),
						Outcome:   graph.OutcomeSuccess,
						Reason:    "running models enumerated",
					})
					checkDetails[checkID] = map[string]any{
						"http_status":          resp.StatusCode,
						"running_models_count": len(ps.Models),
						"truncated":            psTruncated,
					}
				} else {
					psReason := "invalid JSON response from ps endpoint"
					if resp.Truncated {
						responseTruncated = true
						psReason = "ps response truncated at max_response_bytes limit"
					}
					degraded = append(degraded, psReason)
					checkResults = append(checkResults, graph.CheckResult{
						CheckID:   checkID,
						Operation: op,
						TargetID:  srvID.ID(),
						Outcome:   graph.OutcomeFailed,
						Reason:    psReason,
					})
					checkDetails[checkID] = map[string]any{"http_status": resp.StatusCode, "truncated": resp.Truncated}
				}
			case http.StatusNotFound:
				checkResults = append(checkResults, graph.CheckResult{
					CheckID:   checkID,
					Operation: op,
					TargetID:  srvID.ID(),
					Outcome:   graph.OutcomeFailed,
					Reason:    "HTTP 404 not found (running models endpoint unavailable on this version)",
				})
				degraded = append(degraded, "running models endpoint unavailable (HTTP 404)")
				checkDetails[checkID] = map[string]any{"http_status": resp.StatusCode}
			case http.StatusUnauthorized, http.StatusForbidden:
				checkResults = append(checkResults, graph.CheckResult{
					CheckID:   checkID,
					Operation: op,
					TargetID:  srvID.ID(),
					Outcome:   graph.OutcomeDenied,
					Reason:    fmt.Sprintf("HTTP %d: authentication or authorization required", resp.StatusCode),
				})
				degraded = append(degraded, fmt.Sprintf("running models endpoint denied (HTTP %d)", resp.StatusCode))
				checkDetails[checkID] = map[string]any{"http_status": resp.StatusCode}
			default:
				checkResults = append(checkResults, graph.CheckResult{
					CheckID:   checkID,
					Operation: op,
					TargetID:  srvID.ID(),
					Outcome:   graph.OutcomeFailed,
					Reason:    fmt.Sprintf("HTTP %d unexpected status", resp.StatusCode),
				})
				degraded = append(degraded, fmt.Sprintf("running models endpoint returned HTTP %d", resp.StatusCode))
				checkDetails[checkID] = map[string]any{"http_status": resp.StatusCode}
			}
		}
	}

	// 4. Check: Model Provenance & Content Tier (POST /api/show)
	var contentSummary *graph.ContentSummary
	var contentTruncated bool
	{
		checkID := CheckShow
		op := "ollama_show"
		contentEnabled := c.cfg.Content.EnabledFor(Surface)

		if !contentEnabled {
			checkResults = append(checkResults, graph.CheckResult{
				CheckID:   checkID,
				Operation: op,
				TargetID:  srvID.ID(),
				Outcome:   graph.OutcomeSkipped,
				Reason:    "content collection disabled by policy",
			})
			checkDetails[checkID] = map[string]any{"skipped": true, "policy": "content_disabled"}
		} else if len(catalogModels) == 0 {
			checkResults = append(checkResults, graph.CheckResult{
				CheckID:   checkID,
				Operation: op,
				TargetID:  srvID.ID(),
				Outcome:   graph.OutcomeSkipped,
				Reason:    "no models available to query show metadata",
			})
			checkDetails[checkID] = map[string]any{"skipped": true}
		} else {
			budget := content.NewBudget(c.cfg.Content, secrets.NewRedactor(c.cfg.Secrets))
			successCount := 0
			sysFound := false
			cfgFound := false
			showProvenance := make(map[string]map[string]any)
			var showErrors []string
			maxShowAttempts := c.cfg.Bounds.MaxItems
			if maxShowAttempts <= 0 {
				maxShowAttempts = 10000
			}
			showAttempts := 0
			for _, m := range catalogModels {
				modelName := strings.TrimSpace(m.Name)
				if modelName == "" {
					modelName = strings.TrimSpace(m.Model)
				}
				if modelName == "" {
					continue
				}
				reqName := m.Name
				if showAttempts >= maxShowAttempts {
					budget.MarkTruncated(fmt.Sprintf("model show reads reached max_items (%d)", maxShowAttempts))
					break
				}
				showAttempts++
				if reqName == "" {
					reqName = m.Model
				}
				showReqBody, _ := json.Marshal(ShowRequest{Name: reqName})
				resp, showErr := c.transport.Post(ctx, baseURL+"/api/show", "application/json", showReqBody)
				absorb(resp)
				if showErr != nil {
					showErrors = append(showErrors, fmt.Sprintf("%s: %s", reqName, sanitizeError(showErr)))
					continue
				}
				if resp.StatusCode != http.StatusOK {
					showErrors = append(showErrors, fmt.Sprintf("%s: HTTP %d", reqName, resp.StatusCode))
					continue
				}
				if resp.Truncated {
					responseTruncated = true
					budget.MarkTruncated(fmt.Sprintf("show response for %s truncated at max_response_bytes", reqName))
					showErrors = append(showErrors, fmt.Sprintf("%s: response truncated at max_response_bytes limit", reqName))
					continue
				}
				var showResp ShowResponse
				if err := json.Unmarshal(resp.Body, &showResp); err != nil {
					showErrors = append(showErrors, fmt.Sprintf("%s: invalid JSON", reqName))
					continue
				}
				sp := redactProvenance(ShowProvenance{Details: showResp.Details, License: showResp.License})
				provenance[m.Name] = sp
				showProvenance[m.Name] = map[string]any{
					"parent_model": sp.Details.ParentModel,
					"family":       sp.Details.Family,
					"license":      sp.License,
				}
				successCount++

				resID := ""
				if modelID, idErr := graph.NewResourceIdentity(scope, graph.AIModel, srvID, modelName); idErr == nil {
					resID = modelID.ID()
				}
				for _, part := range []struct {
					kind   content.Kind
					suffix string
					body   string
					isSys  bool
					isCfg  bool
				}{
					{content.KindSystemPrompt, "#system", showResp.System, true, false},
					{content.KindModelfile, "#modelfile", showResp.Modelfile, false, true},
					{content.KindTemplate, "#template", showResp.Template, false, true},
					{content.KindConfig, "#parameters", showResp.Parameters, false, true},
				} {
					if strings.TrimSpace(part.body) == "" {
						continue
					}
					if ok, _ := budget.ClaimResourceItem(modelName); !ok {
						break
					}
					rec, added, addErr := budget.Add(content.RecordInput{
						DeploymentScope: scope,
						ScanID:          scanID,
						VantageKey:      vantageKey,
						ServiceID:       srvID.ID(),
						ResourceID:      resID,
						Surface:         Surface,
						CheckID:         checkID,
						Source:          baseURL + "/api/show",
						Kind:            part.kind,
						Location:        modelName + part.suffix,
						MediaType:       "text/plain",
						ObservedAt:      obsTime,
						Body:            part.body,
					})
					if addErr != nil {
						return checkpoint.Result{}, fmt.Errorf("create ollama content record: %w", addErr)
					}
					if added {
						if part.isSys {
							sysFound = true
						}
						if part.isCfg {
							cfgFound = true
						}
						if c.contentSink != nil {
							if err := c.contentSink.Write(rec); err != nil {
								return checkpoint.Result{}, fmt.Errorf("write ollama content record: %w", err)
							}
						}
					}
				}
			}

			contentTruncated = budget.Truncated()
			allClean := successCount == len(catalogModels) && len(showErrors) == 0 && !contentTruncated
			var sysPtr, cfgPtr *bool
			if sysFound {
				v := true
				sysPtr = &v
			} else if allClean {
				v := false
				sysPtr = &v
			}
			if cfgFound {
				v := true
				cfgPtr = &v
			} else if allClean {
				v := false
				cfgPtr = &v
			}
			contentSummary = &graph.ContentSummary{
				Collected:           true,
				Bytes:               budget.Bytes(),
				Truncated:           contentTruncated,
				SystemPromptPresent: sysPtr,
				ConfigCollected:     cfgPtr,
				SecretTypes:         budget.SecretTypes(),
				SecretConfirmedAt:   obsTime,
			}

			if successCount > 0 {
				checkResults = append(checkResults, graph.CheckResult{
					CheckID:   checkID,
					Operation: op,
					TargetID:  srvID.ID(),
					Outcome:   graph.OutcomeSuccess,
					Reason:    fmt.Sprintf("model provenance retrieved for %d of %d models", successCount, len(catalogModels)),
				})
				successDetails := map[string]any{
					"success_count":     successCount,
					"provenance":        showProvenance,
					"content_items":     len(budget.Records()),
					"content_bytes":     budget.Bytes(),
					"content_truncated": contentTruncated,
					"errors":            showErrors,
				}
				if found := budget.Findings(); len(found) > 0 {
					successDetails["detected_exposures"] = content.ExposureDetails(found)
				}
				checkDetails[checkID] = successDetails
				if len(showErrors) > 0 {
					degraded = append(degraded, fmt.Sprintf("model provenance retrieved for %d of %d models", successCount, len(catalogModels)))
				}
			} else {
				checkResults = append(checkResults, graph.CheckResult{
					CheckID:   checkID,
					Operation: op,
					TargetID:  srvID.ID(),
					Outcome:   graph.OutcomeFailed,
					Reason:    fmt.Sprintf("failed to retrieve model provenance: %s", strings.Join(showErrors, "; ")),
				})
				degraded = append(degraded, "model provenance retrieval failed for all models")
				checkDetails[checkID] = map[string]any{"errors": showErrors}
			}
		}
	}

	// 5. Evaluate final Coverage and CoverageReason
	var finalCoverage graph.Coverage
	var finalCoverageReason string
	var finalStatus checkpoint.TargetStatus

	verSuccess := false
	tagsSuccess := false
	for _, cr := range checkResults {
		if cr.CheckID == CheckVersion && cr.Outcome == graph.OutcomeSuccess {
			verSuccess = true
		}
		if cr.CheckID == CheckTags && cr.Outcome == graph.OutcomeSuccess {
			tagsSuccess = true
		}
	}

	if totalTransportFailures >= 2 && !verSuccess && !tagsSuccess {
		// Complete transport failure (target unreachable)
		finalCoverage = graph.CoverageFailed
		finalStatus = checkpoint.TargetStatusFailed
		if versionCheckErr != nil {
			finalCoverageReason = fmt.Sprintf("target unreachable: %s", sanitizeError(versionCheckErr))
		} else if tagsCheckErr != nil {
			finalCoverageReason = fmt.Sprintf("target unreachable: %s", sanitizeError(tagsCheckErr))
		} else {
			finalCoverageReason = "target unreachable on all endpoints"
		}
	} else if totalDeniedCount >= 2 && !verSuccess && !tagsSuccess {
		// All endpoints denied access
		finalCoverage = graph.CoveragePartial
		finalStatus = checkpoint.TargetStatusPartial
		finalCoverageReason = "authentication required: all metadata endpoints denied access"
	} else if verSuccess && tagsSuccess {
		if catalogTruncated || psTruncated || responseTruncated || contentTruncated {
			var reasons []string
			if catalogTruncated {
				reasons = append(reasons, "model catalog truncated at max_items bound")
			}
			if psTruncated {
				reasons = append(reasons, "running models truncated at max_items bound")
			}
			if responseTruncated {
				reasons = append(reasons, "response body truncated at max_response_bytes bound")
			}
			if contentTruncated {
				reasons = append(reasons, "content tier truncated at configured bounds")
			}
			finalCoverage = graph.CoverageTruncated
			finalStatus = checkpoint.TargetStatusPartial
			finalCoverageReason = strings.Join(reasons, "; ")
		} else if len(degraded) > 0 {
			finalCoverage = graph.CoveragePartial
			finalStatus = checkpoint.TargetStatusPartial
			finalCoverageReason = strings.Join(degraded, "; ")
		} else {
			finalCoverage = graph.CoverageComplete
			finalStatus = checkpoint.TargetStatusCompleted
			finalCoverageReason = "" // CoverageComplete requires empty reason
		}
	} else if tagsSuccess && !verSuccess {
		finalCoverage = graph.CoveragePartial
		finalStatus = checkpoint.TargetStatusPartial
		finalCoverageReason = "model catalog enumerated, but runtime version endpoint unavailable or failed"
	} else if verSuccess && !tagsSuccess {
		finalCoverage = graph.CoveragePartial
		finalStatus = checkpoint.TargetStatusPartial
		finalCoverageReason = "runtime version reported, but model catalog enumeration unavailable or denied"
	} else {
		finalCoverage = graph.CoverageFailed
		finalStatus = checkpoint.TargetStatusFailed
		finalCoverageReason = "enumeration failed: neither version nor model catalog endpoints succeeded"
	}

	// 6. Construct validated final Observation
	obs := graph.Observation{
		SchemaVersion:    "1",
		ScanID:           scanID,
		CollectorVersion: "0.1.0",
		EvidenceID:       evidenceID,
		Source:           sourceURL,
		Surface:          Surface,
		ObservedAt:       obsTime.UTC(),
		DeploymentScope:  scope,
		VantageKey:       vantageKey,
		Coverage:         finalCoverage,
		CoverageReason:   finalCoverageReason,
	}
	if err := obs.Validate(scope); err != nil {
		return checkpoint.Result{}, fmt.Errorf("validate observation: %w", err)
	}

	// Anonymous access is recorded as flat service properties, never as edges.
	// Successes come from the enumeration check; any denied check is an observed
	// authentication boundary.
	var accessEvidence []graph.AccessEvidence
	if accessEv != nil {
		accessEv.Observation = obs // also backs the evidence-sidecar record below
		accessEvidence = append(accessEvidence, *accessEv)
	}
	for _, cr := range checkResults {
		if cr.Outcome == graph.OutcomeDenied {
			accessEvidence = append(accessEvidence, graph.AccessEvidence{
				Observation: obs, CheckID: cr.CheckID, Operation: cr.Operation, TargetID: srvID.ID(),
				Outcome: graph.OutcomeDenied, Reason: cr.Reason, OperationKind: graph.EnumerationOperation,
			})
		}
	}
	access := graph.SummarizeAccess(accessEvidence)

	// 7. Build Graph Nodes (only when the target was positively fingerprinted or denied)
	var nodes []emitter.NodeItem
	var edges []graph.Edge
	var evidenceRecords []evidence.Record

	if finalCoverage != graph.CoverageFailed {
		// Service node: OllamaInstance
		srvNode, err := graph.NewNode(srvID, obs)
		if err != nil {
			return checkpoint.Result{}, fmt.Errorf("create service node: %w", err)
		}

		facts := graph.ServiceFacts{
			Endpoint: ep, Name: fmt.Sprintf("OLLAMA · %s:%d", ep.Host(), ep.Port()),
			Product: "Ollama", Vendor: "Ollama", VantageKey: vantageKey, Access: access,
			// Ollama's documented API includes pull, copy, and delete; this is
			// inferred from product identity, not exercised.
			ExecSurface: []string{graph.ExecModelMutation}, ExecSurfaceBasis: graph.BasisInferred,
			Content: contentSummary,
		}
		if tlsInfo != nil {
			facts.TLS = &graph.TLSSummary{
				Result: tlsInfo.VerificationResult, Reason: tlsInfo.VerificationReason,
				LeafSHA256: tlsInfo.CertFingerprint, Issuer: tlsInfo.Issuer, NotAfter: tlsInfo.ValidTo,
				TLSVersion: tlsInfo.NegotiatedVersion, InsecureSet: tlsInfo.InsecureOverride,
			}
		}
		srvProps := facts.Properties()
		if reportedVersion != "" {
			srvProps["software_version"] = reportedVersion
		}
		if rawReportedVersion != "" {
			srvProps["software_version_raw"] = rawReportedVersion
		}

		srvItem, err := emitter.NewNodeItem(srvNode, srvProps)
		if err != nil {
			return checkpoint.Result{}, fmt.Errorf("create service node item: %w", err)
		}
		nodes = append(nodes, srvItem)

		// Map of running model names for fast lookup
		runningMap := make(map[string]ModelInfo)
		for _, rm := range runningModels {
			runningMap[rm.Name] = rm
			if rm.Model != "" {
				runningMap[rm.Model] = rm
			}
		}

		// Model nodes: AIModel
		for _, m := range catalogModels {
			modelName := strings.TrimSpace(m.Name)
			if modelName == "" {
				modelName = strings.TrimSpace(m.Model)
			}
			if modelName == "" {
				continue
			}

			modelID, mErr := graph.NewResourceIdentity(scope, graph.AIModel, srvID, modelName)
			if mErr != nil {
				continue
			}
			modelNode, mErr := graph.NewNode(modelID, obs)
			if mErr != nil {
				continue
			}

			modelProps := map[string]any{
				"name": strings.ToUpper(modelName),
			}
			if m.Digest != "" {
				modelProps["digest"] = m.Digest
			}
			if m.Size > 0 {
				modelProps["size"] = m.Size
			}
			if m.Details.Format != "" {
				modelProps["format"] = m.Details.Format
			}
			if m.Details.Family != "" {
				modelProps["family"] = m.Details.Family
			}
			if m.Details.ParameterSize != "" {
				modelProps["parameter_size"] = m.Details.ParameterSize
			}
			if m.Details.QuantizationLevel != "" {
				modelProps["quantization_level"] = m.Details.QuantizationLevel
			}
			if m.Details.ParentModel != "" {
				modelProps["parent_model"] = m.Details.ParentModel
			}
			if m.ModifiedAt != "" {
				modelProps["modified_at"] = m.ModifiedAt
			}
			if sp, ok := provenance[m.Name]; ok {
				if sp.Details.ParentModel != "" {
					modelProps["parent_model"] = sp.Details.ParentModel
				}
				if sp.Details.Family != "" {
					modelProps["family"] = sp.Details.Family
				}
				if sp.License != "" {
					modelProps["license"] = sp.License
				}
				modelProps["provenance_source"] = "api_show"
			}
			if rm, ok := runningMap[modelName]; ok {
				modelProps["running"] = true
				if rm.SizeVRAM > 0 {
					modelProps["size_vram"] = rm.SizeVRAM
				}
				if rm.ExpiresAt != "" {
					modelProps["expires_at"] = rm.ExpiresAt
				}
			}

			modelItem, mErr := emitter.NewNodeItem(modelNode, modelProps)
			if mErr != nil {
				continue
			}
			nodes = append(nodes, modelItem)

			// Topology Edge: ProvidesModel (OllamaInstance -> AIModel)
			pmEdge, pmErr := graph.NewTopologyEdge(graph.ProvidesModel, srvID.Reference(), modelID.Reference(), obs)
			if pmErr == nil {
				edges = append(edges, pmEdge)
			}
		}

		// 8. Attachment: an existing native node when the mapping names one,
		// otherwise a scoped NetworkEndpoint fallback.
		corrResult, cErr := resolver.Resolve(scope, targetHost)
		if cErr != nil {
			return checkpoint.Result{}, fmt.Errorf("correlate target: %w", cErr)
		}
		if fbID, ok := corrResult.FallbackIdentity(); ok {
			netNode, err := graph.NewNode(fbID, obs)
			if err != nil {
				return checkpoint.Result{}, fmt.Errorf("create fallback node: %w", err)
			}
			netItem, err := emitter.NewNodeItem(netNode, map[string]any{
				"name":         strings.ToUpper(corrResult.Evidence().NormalizedTarget),
				"target_type":  string(corrResult.Evidence().TargetType),
				"target_value": corrResult.Evidence().NormalizedTarget,
			})
			if err != nil {
				return checkpoint.Result{}, fmt.Errorf("create fallback node item: %w", err)
			}
			nodes = append(nodes, netItem)
		}
		observedAt, err := corrResult.ObservedAt(srvID, obs)
		if err != nil {
			return checkpoint.Result{}, fmt.Errorf("create ObservedAt edge: %w", err)
		}
		edges = append(edges, observedAt)
		corrObs := obs
		corrObs.EvidenceID = evidenceID + "-correlation"
		corrRec, err := evidence.NewCorrelationRecord(corrResult.Evidence(), corrObs)
		if err != nil {
			return checkpoint.Result{}, fmt.Errorf("create correlation record: %w", err)
		}
		evidenceRecords = append(evidenceRecords, corrRec)
	}

	// 10. Assemble Evidence Sidecar Records
	for _, cr := range checkResults {
		crObs := obs
		crObs.EvidenceID = evidenceID + "-" + cr.CheckID
		cr.Observation = crObs
		details := checkDetails[cr.CheckID]
		if cr.CheckID == CheckTags && accessEv != nil {
			ev := *accessEv
			ev.Observation = crObs
			rec, err := evidence.NewAccessEvidenceRecord(ev, details)
			if err == nil {
				evidenceRecords = append(evidenceRecords, rec)
				continue
			}
		}
		rec, err := evidence.NewCheckResultRecord(cr, details)
		if err == nil {
			evidenceRecords = append(evidenceRecords, rec)
		}
	}

	if fpInput != nil {
		fpObs := obs
		fpObs.EvidenceID = evidenceID + "-fingerprint"
		fpInput.Observation = fpObs
		rec, err := evidence.NewFingerprintRecord(*fpInput)
		if err == nil {
			evidenceRecords = append(evidenceRecords, rec)
		}
	}

	if tlsInfo != nil {
		tlsObs := obs
		tlsObs.EvidenceID = evidenceID + "-tls"
		tlsInput := evidence.TLSRecordInput{
			Observation:        tlsObs,
			TargetID:           srvID.ID(),
			CertFingerprint:    tlsInfo.CertFingerprint,
			Issuer:             tlsInfo.Issuer,
			Subject:            tlsInfo.Subject,
			SANs:               tlsInfo.SANs,
			ValidFrom:          tlsInfo.ValidFrom,
			ValidTo:            tlsInfo.ValidTo,
			VerificationResult: tlsInfo.VerificationResult,
			VerificationReason: tlsInfo.VerificationReason,
			NegotiatedVersion:  tlsInfo.NegotiatedVersion,
			InsecureOverride:   tlsInfo.InsecureOverride,
		}
		rec, err := evidence.NewTLSRecord(tlsInput)
		if err == nil {
			evidenceRecords = append(evidenceRecords, rec)
		}
	}

	for i, red := range redirects {
		redObs := obs
		redObs.EvidenceID = fmt.Sprintf("%s-redirect-%d", evidenceID, i)
		redInput := evidence.RedirectRecordInput{
			Observation: redObs,
			FromURL:     red.FromURL,
			ToURL:       red.ToURL,
			StatusCode:  red.StatusCode,
			Authorized:  red.Authorized,
			Reason:      red.Reason,
		}
		rec, err := evidence.NewRedirectRecord(redInput)
		if err == nil {
			evidenceRecords = append(evidenceRecords, rec)
		}
	}

	res := checkpoint.Result{
		Target:      target,
		Surface:     Surface,
		Observation: obs,
		Status:      finalStatus,
		Nodes:       nodes,
		Edges:       edges,
		Evidence:    evidenceRecords,
	}

	if err := res.Validate(scope); err != nil {
		return checkpoint.Result{}, fmt.Errorf("validate result: %w", err)
	}

	return res, nil
}

// CollectToJournal performs collection and records the resulting progress and entries to j.
func (c *Collector) CollectToJournal(
	ctx context.Context,
	target string,
	j checkpoint.Journal,
	resolver *correlate.Resolver,
) (checkpoint.Result, error) {
	if j == nil {
		return checkpoint.Result{}, errors.New("nil journal")
	}

	header := j.Header()
	t, err := time.Parse(time.RFC3339, header.CreatedAt)
	if err != nil {
		t = time.Now().UTC()
	}

	res, err := c.Collect(ctx, target, header.DeploymentScope, header.VantageKey, header.ScanID, t, resolver)
	if err != nil {
		return checkpoint.Result{}, err
	}

	if err := j.RecordResult(res); err != nil {
		return res, fmt.Errorf("record result in journal: %w", err)
	}
	if err := j.Flush(); err != nil {
		return res, fmt.Errorf("flush journal: %w", err)
	}
	return res, nil
}

func redactProvenance(sp ShowProvenance) ShowProvenance {
	return ShowProvenance{
		Details: ModelDetails{
			ParentModel: truncateField(sp.Details.ParentModel),
			Family:      truncateField(sp.Details.Family),
		},
		License: truncateField(sp.License),
	}
}

func truncateField(v string) string {
	v = strings.TrimSpace(v)
	if r := []rune(v); len(r) > maxProvenanceFieldLen {
		return string(r[:maxProvenanceFieldLen])
	}
	return v
}

func normalizeVersion(raw string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "v")
	raw = strings.TrimPrefix(raw, "V")
	return raw
}

func sanitizeError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	// Strip userinfo or query strings if present
	if strings.Contains(msg, "@") || strings.Contains(msg, "?") {
		msg = evidence.SanitizeURL(msg)
	}
	for len(msg) > 0 && (msg[len(msg)-1] == '\n' || msg[len(msg)-1] == '\r') {
		msg = msg[:len(msg)-1]
	}
	return msg
}

func generateEvidenceID(scanID, targetID string, t time.Time) string {
	raw := fmt.Sprintf("%s:%s:%d", scanID, targetID, t.UnixNano())
	sum := sha256.Sum256([]byte(raw))
	return "ev-ollama-" + hex.EncodeToString(sum[:8])
}
