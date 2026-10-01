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
	"strings"
	"time"

	"github.com/0x3df/LLMHound/internal/checkpoint"
	"github.com/0x3df/LLMHound/internal/config"
	"github.com/0x3df/LLMHound/internal/correlate"
	"github.com/0x3df/LLMHound/internal/emitter"
	"github.com/0x3df/LLMHound/internal/evidence"
	"github.com/0x3df/LLMHound/internal/graph"
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

// ShowProvenance is the only part of the POST /api/show payload that is decoded.
// Modelfile, system prompt, and template content are never decoded or retained.
type ShowProvenance struct {
	Details ModelDetails `json:"details,omitempty"`
	License string       `json:"license,omitempty"`
}

const maxProvenanceFieldLen = 200

// Collector implements Ollama surface enumeration.
type Collector struct {
	cfg       config.Config
	transport *transport.Client
}

// Option configures Collector behavior.
type Option func(*Collector)

// WithTransport sets a custom transport client.
func WithTransport(tc *transport.Client) Option {
	return func(c *Collector) {
		c.transport = tc
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
		// Determine default scheme and port
		scheme := "http"
		hostPart := rawURL
		if strings.HasPrefix(hostPart, "https://") {
			scheme = "https"
			hostPart = strings.TrimPrefix(hostPart, "https://")
		} else if strings.HasPrefix(hostPart, "http://") {
			hostPart = strings.TrimPrefix(hostPart, "http://")
		}

		if _, _, err := net.SplitHostPort(hostPart); err != nil {
			// No port specified, append standard Ollama port
			rawURL = fmt.Sprintf("%s://%s:%d", scheme, hostPart, DefaultPort)
		} else {
			rawURL = fmt.Sprintf("%s://%s", scheme, hostPart)
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
	vantage graph.Identity,
	scanID string,
	obsTime time.Time,
	resolver *correlate.Resolver,
	verifiedComputers []correlate.Computer,
) (checkpoint.Result, error) {
	if vantage.Kind() != graph.CollectionVantage {
		return checkpoint.Result{}, errors.New("vantage must be CollectionVantage")
	}
	scope := vantage.Scope()

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
	var runningModels []ModelInfo
	var degraded []string
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
			if resp != nil && resp.TLS != nil {
				tlsInfo = resp.TLS
			}
			if resp != nil && len(resp.Redirects) > 0 {
				redirects = append(redirects, resp.Redirects...)
			}
		} else {
			if resp.TLS != nil {
				tlsInfo = resp.TLS
			}
			if len(resp.Redirects) > 0 {
				redirects = append(redirects, resp.Redirects...)
			}

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
			if resp != nil && resp.TLS != nil && tlsInfo == nil {
				tlsInfo = resp.TLS
			}
			if resp != nil && len(resp.Redirects) > 0 {
				redirects = append(redirects, resp.Redirects...)
			}
		} else {
			if resp.TLS != nil && tlsInfo == nil {
				tlsInfo = resp.TLS
			}
			if len(resp.Redirects) > 0 {
				redirects = append(redirects, resp.Redirects...)
			}

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

	// 4. Check: Detailed Model Metadata (POST /api/show) - Sensitive reads requiring opt-in
	{
		checkID := CheckShow
		op := "ollama_show"
		hasOptIn := c.cfg.OptIns.Prompts || c.cfg.OptIns.ConfigurationContent || c.cfg.OptIns.ResourceContent

		if !hasOptIn {
			checkResults = append(checkResults, graph.CheckResult{
				CheckID:   checkID,
				Operation: op,
				TargetID:  srvID.ID(),
				Outcome:   graph.OutcomeSkipped,
				Reason:    "sensitive template/modelfile read requires explicit opt-in",
			})
			checkDetails[checkID] = map[string]any{"skipped": true, "policy": "default_read_only"}
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
			// Query /api/show for models with bounds and sanitization
			successCount := 0
			showProvenance := make(map[string]map[string]any)
			var showErrors []string
			for _, m := range catalogModels {
				showReqBody, _ := json.Marshal(ShowRequest{Name: m.Name})
				resp, showErr := c.transport.Post(ctx, baseURL+"/api/show", "application/json", showReqBody)
				if showErr != nil {
					showErrors = append(showErrors, fmt.Sprintf("%s: %s", m.Name, sanitizeError(showErr)))
					continue
				}
				var sp ShowProvenance
				if resp.StatusCode == http.StatusOK && json.Unmarshal(resp.Body, &sp) == nil {
					sp = redactProvenance(sp)
					provenance[m.Name] = sp
					showProvenance[m.Name] = map[string]any{
						"parent_model": sp.Details.ParentModel,
						"family":       sp.Details.Family,
						"license":      sp.License,
					}
					successCount++
				} else if resp.StatusCode == http.StatusOK {
					showErrors = append(showErrors, fmt.Sprintf("%s: invalid JSON", m.Name))
				} else {
					showErrors = append(showErrors, fmt.Sprintf("%s: HTTP %d", m.Name, resp.StatusCode))
				}
			}

			if successCount > 0 {
				checkResults = append(checkResults, graph.CheckResult{
					CheckID:   checkID,
					Operation: op,
					TargetID:  srvID.ID(),
					Outcome:   graph.OutcomeSuccess,
					Reason:    fmt.Sprintf("model provenance retrieved for %d of %d models", successCount, len(catalogModels)),
				})
				checkDetails[checkID] = map[string]any{
					"success_count": successCount,
					"provenance":    showProvenance,
					"errors":        showErrors,
				}
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
		if catalogTruncated || responseTruncated {
			finalCoverage = graph.CoverageTruncated
			finalStatus = checkpoint.TargetStatusPartial
			finalCoverageReason = "model catalog or running models truncated by max_items or max_response_bytes limit"
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
		Vantage:          vantage,
		Coverage:         finalCoverage,
		CoverageReason:   finalCoverageReason,
	}
	if err := obs.Validate(scope); err != nil {
		return checkpoint.Result{}, fmt.Errorf("validate observation: %w", err)
	}

	// 7. Build Graph Nodes
	var nodes []emitter.NodeItem

	// Service node: OllamaInstance
	srvNode, err := graph.NewNode(srvID, obs)
	if err != nil {
		return checkpoint.Result{}, fmt.Errorf("create service node: %w", err)
	}

	srvProps := map[string]any{
		"name":          fmt.Sprintf("OLLAMA · %s:%d", ep.Host(), ep.Port()),
		"endpoint_host": ep.Host(),
		"endpoint_port": int(ep.Port()),
		"product":       "Ollama",
		"vendor":        "Ollama",
	}
	if reportedVersion != "" {
		srvProps["software_version"] = reportedVersion
	}
	if rawReportedVersion != "" {
		srvProps["software_version_raw"] = rawReportedVersion
	}
	if tlsInfo != nil {
		if tlsInfo.VerificationResult != "" {
			srvProps["tls_verification"] = tlsInfo.VerificationResult
		}
		if tlsInfo.CertFingerprint != "" {
			srvProps["tls_fingerprint"] = tlsInfo.CertFingerprint
		}
		if tlsInfo.NegotiatedVersion != "" {
			srvProps["tls_negotiated_version"] = tlsInfo.NegotiatedVersion
		}
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
	var edges []graph.Edge
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

	// 8. Build Access Edge (if anonymous tags access succeeded)
	if accessEv != nil {
		accessEv.Observation = obs
		accessEdge, aErr := graph.NewAccessEdge(graph.UnauthenticatedAccess, vantage.Reference(), srvID.Reference(), *accessEv)
		if aErr == nil {
			edges = append(edges, accessEdge)
		}
	}

	// 9. Computer Correlation
	var evidenceRecords []evidence.Record

	if resolver != nil {
		corrResult, cErr := resolver.Resolve(scope, targetHost, verifiedComputers)
		if cErr == nil && corrResult.Evidence().Verified {
			linkingEdge, lErr := corrResult.ObservedAt(srvID, obs)
			if lErr == nil {
				edges = append(edges, linkingEdge)
			}
			corrRec, rErr := evidence.NewCorrelationRecord(corrResult.Evidence(), obs)
			if rErr == nil {
				evidenceRecords = append(evidenceRecords, corrRec)
			}
		} else if cErr == nil {
			if fbID, ok := corrResult.FallbackIdentity(); ok {
				netNode, nnErr := graph.NewNode(fbID, obs)
				if nnErr == nil {
					netItem, niErr := emitter.NewNodeItem(netNode, map[string]any{
						"name":         strings.ToUpper(corrResult.Evidence().NormalizedTarget),
						"target_type":  string(corrResult.Evidence().TargetType),
						"target_value": corrResult.Evidence().NormalizedTarget,
					})
					if niErr == nil {
						nodes = append(nodes, netItem)
					}
				}
			}
			obsEdge, oErr := corrResult.ObservedAt(srvID, obs)
			if oErr == nil {
				edges = append(edges, obsEdge)
			}
			corrRec, rErr := evidence.NewCorrelationRecord(corrResult.Evidence(), obs)
			if rErr == nil {
				evidenceRecords = append(evidenceRecords, corrRec)
			}
		} else {
			netTarget, pErr := graph.ParseTarget(targetHost)
			if pErr == nil {
				netID, nErr := graph.NewNetworkEndpointIdentity(scope, netTarget)
				if nErr == nil {
					netNode, nnErr := graph.NewNode(netID, obs)
					if nnErr == nil {
						netItem, niErr := emitter.NewNodeItem(netNode, map[string]any{
							"name":         strings.ToUpper(targetHost),
							"target_type":  string(netTarget.Type()),
							"target_value": netTarget.Value(),
						})
						if niErr == nil {
							nodes = append(nodes, netItem)
						}
					}
					corr := graph.Correlation{
						FallbackReason: cErr.Error(),
					}
					obsEdge, oErr := graph.NewObservedAtEdge(srvID.Reference(), netID.Reference(), obs, corr)
					if oErr == nil {
						edges = append(edges, obsEdge)
					}
					ev := correlate.Evidence{
						OriginalTarget:   targetHost,
						NormalizedTarget: netTarget.Value(),
						TargetType:       netTarget.Type(),
						Verified:         false,
						Correlation:      corr,
					}
					corrRec, rErr := evidence.NewCorrelationRecord(ev, obs)
					if rErr == nil {
						evidenceRecords = append(evidenceRecords, corrRec)
					}
				}
			}
		}
	} else {
		// Fallback without resolver
		netTarget, pErr := graph.ParseTarget(targetHost)
		if pErr == nil {
			netID, nErr := graph.NewNetworkEndpointIdentity(scope, netTarget)
			if nErr == nil {
				netNode, nnErr := graph.NewNode(netID, obs)
				if nnErr == nil {
					netItem, niErr := emitter.NewNodeItem(netNode, map[string]any{
						"name":         strings.ToUpper(targetHost),
						"target_type":  string(netTarget.Type()),
						"target_value": netTarget.Value(),
					})
					if niErr == nil {
						nodes = append(nodes, netItem)
					}
				}
				corr := graph.Correlation{
					FallbackReason: "no correlation resolver configured",
				}
				obsEdge, oErr := graph.NewObservedAtEdge(srvID.Reference(), netID.Reference(), obs, corr)
				if oErr == nil {
					edges = append(edges, obsEdge)
				}
				ev := correlate.Evidence{
					OriginalTarget:   targetHost,
					NormalizedTarget: netTarget.Value(),
					TargetType:       netTarget.Type(),
					Verified:         false,
					Correlation:      corr,
				}
				corrRec, rErr := evidence.NewCorrelationRecord(ev, obs)
				if rErr == nil {
					evidenceRecords = append(evidenceRecords, corrRec)
				}
			}
		}
	}

	// 10. Assemble Evidence Sidecar Records
	for _, cr := range checkResults {
		cr.Observation = obs
		details := checkDetails[cr.CheckID]
		if cr.CheckID == CheckTags && accessEv != nil {
			rec, err := evidence.NewAccessEvidenceRecord(*accessEv, details)
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
		fpInput.Observation = obs
		rec, err := evidence.NewFingerprintRecord(*fpInput)
		if err == nil {
			evidenceRecords = append(evidenceRecords, rec)
		}
	}

	if tlsInfo != nil {
		tlsInput := evidence.TLSRecordInput{
			Observation:        obs,
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

	for _, red := range redirects {
		redInput := evidence.RedirectRecordInput{
			Observation: obs,
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
	verifiedComputers []correlate.Computer,
) (checkpoint.Result, error) {
	if j == nil {
		return checkpoint.Result{}, errors.New("nil journal")
	}

	header := j.Header()
	vantage, err := graph.NewVantageIdentity(header.DeploymentScope, header.VantageKey)
	if err != nil {
		return checkpoint.Result{}, fmt.Errorf("reconstruct vantage identity: %w", err)
	}

	t, err := time.Parse(time.RFC3339, header.CreatedAt)
	if err != nil {
		t = time.Now().UTC()
	}

	res, err := c.Collect(ctx, target, vantage, header.ScanID, t, resolver, verifiedComputers)
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
