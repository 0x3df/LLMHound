// Package mlflow provides anonymous, read-only metadata enumeration of MLflow
// tracking and model-registry servers (version, experiments, registered models,
// artifact store locations, and allowlisted small text artifacts) without
// mutating state or downloading model weights.
package mlflow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
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
	// Surface is the canonical surface identifier for MLflow.
	Surface = "mlflow"

	// DefaultPort is the default listener port for MLflow servers.
	DefaultPort = 5000

	// Allowlisted check identifiers.
	CheckVersion          = "mlflow_version"
	CheckExperiments      = "mlflow_experiments"
	CheckRegisteredModels = "mlflow_registered_models"
	CheckArtifactsList    = "mlflow_artifacts_list"
	CheckArtifactText     = "mlflow_artifact_text"
)

var allowlistedTextArtifacts = map[string]bool{
	"mlmodel":                    true,
	"requirements.txt":           true,
	"conda.yaml":                 true,
	"python_env.yaml":            true,
	"serving_input_example.json": true,
}

var blockedWeightExtensions = map[string]bool{
	".pkl": true, ".pt": true, ".pth": true, ".bin": true,
	".safetensors": true, ".onnx": true, ".h5": true, ".hdf5": true,
	".joblib": true, ".tar": true, ".gz": true, ".zip": true,
	".ckpt": true, ".pb": true, ".tflite": true, ".gguf": true,
}

type experimentsResponse struct {
	Experiments   []experimentEntry `json:"experiments"`
	NextPageToken string            `json:"next_page_token"`
}

type experimentEntry struct {
	ExperimentID     string `json:"experiment_id"`
	Name             string `json:"name"`
	ArtifactLocation string `json:"artifact_location"`
	LifecycleStage   string `json:"lifecycle_stage"`
}

type registeredModelsResponse struct {
	RegisteredModels []registeredModelEntry `json:"registered_models"`
	NextPageToken    string                 `json:"next_page_token"`
}

type registeredModelEntry struct {
	Name           string               `json:"name"`
	Description    string               `json:"description,omitempty"`
	LatestVersions []modelVersionEntry  `json:"latest_versions"`
	Aliases        []registeredAliasRec `json:"aliases,omitempty"`
}

type registeredAliasRec struct {
	Alias   string `json:"alias"`
	Version string `json:"version"`
}

type modelVersionEntry struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	CurrentStage string `json:"current_stage"`
	Source       string `json:"source"`
	RunID        string `json:"run_id"`
	Status       string `json:"status"`
}

type artifactsListResponse struct {
	RootURI string              `json:"root_uri"`
	Files   []artifactFileEntry `json:"files"`
}

type artifactFileEntry struct {
	Path     string `json:"path"`
	IsDir    bool   `json:"is_dir"`
	FileSize int64  `json:"file_size"`
}

type artifactTarget struct {
	RunID string
	Path  string
	Size  int64
}

// Collector implements anonymous, read-only MLflow enumeration.
type Collector struct {
	cfg         config.Config
	transport   *transport.Client
	contentSink content.Sink
}

// Option configures an MLflow Collector.
type Option func(*Collector)

// WithTransport overrides the transport client (primarily for testing).
func WithTransport(tc *transport.Client) Option {
	return func(c *Collector) {
		c.transport = tc
	}
}

// WithContentSink configures where bounded allowlisted text artifacts are written.
func WithContentSink(sink content.Sink) Option {
	return func(c *Collector) {
		c.contentSink = sink
	}
}

// New constructs an MLflow collector with the given configuration.
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

// Collect performs allowlisted GET metadata checks and bounded allowlisted text
// artifact reads on an MLflow server without downloading weights or mutating state.
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

	srvID, err := graph.NewServiceIdentity(scope, graph.MLflowServer, ep)
	if err != nil {
		return checkpoint.Result{}, fmt.Errorf("create service identity: %w", err)
	}

	evID := common.EvidenceID(scanID, srvID.ID(), obsTime)
	baseURL := strings.TrimSuffix(ep.String(), "/")
	sourceURL := baseURL + "/api/2.0/mlflow/experiments/search"

	var tlsInfo *transport.TLSInfo
	var redirects []transport.RedirectInfo
	var checks []common.CheckEntry
	var degraded []string

	var mlflowConfirmed bool
	var deniedConfirmed bool
	var rawVersion, normVersion string
	var verSuccess, verDenied bool
	var verErr error

	var experiments []experimentEntry
	var expSuccess, expDenied, expTruncated bool
	var expErr error

	var regModels []registeredModelEntry
	var modelsSuccess, modelsDenied, modelsTruncated bool
	var modelsErr error

	var responseTruncated bool

	maxItems := c.cfg.Bounds.MaxItems
	if maxItems <= 0 {
		maxItems = 10000
	}
	maxPages := c.cfg.Bounds.MaxPages
	if maxPages <= 0 {
		maxPages = 100
	}

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
				common.CheckEntry{CheckID: CheckExperiments, Operation: CheckExperiments, Outcome: graph.OutcomeSkipped, Reason: "prerequisite failed: TLS verification failed", OperationKind: graph.EnumerationOperation},
				common.CheckEntry{CheckID: CheckRegisteredModels, Operation: CheckRegisteredModels, Outcome: graph.OutcomeSkipped, Reason: "prerequisite failed: TLS verification failed", OperationKind: graph.EnumerationOperation},
				common.CheckEntry{CheckID: CheckArtifactsList, Operation: CheckArtifactsList, Outcome: graph.OutcomeSkipped, Reason: "prerequisite failed: TLS verification failed", OperationKind: graph.EnumerationOperation},
				common.CheckEntry{CheckID: CheckArtifactText, Operation: CheckArtifactText, Outcome: graph.OutcomeSkipped, Reason: "prerequisite failed: TLS verification failed", OperationKind: graph.ResourceReadOperation},
			)
			return c.buildFailedResult(target, scope, vantageKey, scanID, obsTime, evID, baseURL+"/version", srvID, reason, checks, tlsInfo, redirects)
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
				} else if v, ok := parseMLflowVersionBody(resp.Header, resp.Body); !ok {
					degraded = append(degraded, "invalid or non-version response from /version")
					checks = append(checks, common.CheckEntry{
						CheckID: CheckVersion, Operation: CheckVersion, Outcome: graph.OutcomeFailed,
						Reason: "response from /version is not a valid MLflow plain-text version", OperationKind: graph.EnumerationOperation,
						Details: map[string]any{"http_status": resp.StatusCode},
					})
				} else {
					rawVersion = common.BoundString(v, 128)
					normVersion = common.NormalizeVersion(v)
					verSuccess = true
					checks = append(checks, common.CheckEntry{
						CheckID: CheckVersion, Operation: CheckVersion, Outcome: graph.OutcomeSuccess,
						Reason: fmt.Sprintf("MLflow version reported: %s", rawVersion), Anonymous: true,
						OperationKind: graph.EnumerationOperation, CountForAccess: false,
						Details: map[string]any{
							"http_status":          resp.StatusCode,
							"software_version":     normVersion,
							"software_version_raw": rawVersion,
						},
					})
				}
			case http.StatusUnauthorized, http.StatusForbidden:
				verDenied = true
				if hasMLflowDenial(resp.Header, resp.Body) {
					mlflowConfirmed = true
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
					Reason: "HTTP 404 not found (/version unavailable)", OperationKind: graph.EnumerationOperation,
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

	// 2. Check: GET /api/2.0/mlflow/experiments/search (paginated enumeration).
	{
		pageToken := ""
		pages := 0
		for {
			if pages >= maxPages {
				expTruncated = true
				break
			}
			u := baseURL + "/api/2.0/mlflow/experiments/search?max_results=100"
			if pageToken != "" {
				u += "&page_token=" + url.QueryEscape(pageToken)
			}
			resp, reqErr := c.transport.Get(ctx, u)
			common.AbsorbTransport(resp, &tlsInfo, &redirects)

			if common.IsTLSFailure(tlsInfo, c.cfg.Insecure) {
				reason := common.SanitizeError(reqErr)
				if reason == "" {
					reason = "TLS certificate verification failed: " + common.BoundString(tlsInfo.VerificationReason, 200)
				}
				checks = append(checks,
					common.CheckEntry{
						CheckID: CheckExperiments, Operation: CheckExperiments, Outcome: graph.OutcomeFailed,
						Reason: reason, OperationKind: graph.EnumerationOperation,
						Details: map[string]any{"tls_error": common.BoundString(tlsInfo.VerificationReason, 200)},
					},
					common.CheckEntry{CheckID: CheckRegisteredModels, Operation: CheckRegisteredModels, Outcome: graph.OutcomeSkipped, Reason: "prerequisite failed: TLS verification failed", OperationKind: graph.EnumerationOperation},
					common.CheckEntry{CheckID: CheckArtifactsList, Operation: CheckArtifactsList, Outcome: graph.OutcomeSkipped, Reason: "prerequisite failed: TLS verification failed", OperationKind: graph.EnumerationOperation},
					common.CheckEntry{CheckID: CheckArtifactText, Operation: CheckArtifactText, Outcome: graph.OutcomeSkipped, Reason: "prerequisite failed: TLS verification failed", OperationKind: graph.ResourceReadOperation},
				)
				return c.buildFailedResult(target, scope, vantageKey, scanID, obsTime, evID, sourceURL, srvID, reason, checks, tlsInfo, redirects)
			}

			if reqErr != nil {
				if pages == 0 {
					expErr = reqErr
					reason := common.SanitizeError(reqErr)
					degraded = append(degraded, "experiments check failed: "+reason)
					checks = append(checks, common.CheckEntry{
						CheckID: CheckExperiments, Operation: CheckExperiments, Outcome: graph.OutcomeFailed,
						Reason: reason, OperationKind: graph.EnumerationOperation,
						Details: map[string]any{"error": reason},
					})
				} else {
					degraded = append(degraded, "experiments pagination stopped: "+common.SanitizeError(reqErr))
				}
				break
			}

			pages++
			switch resp.StatusCode {
			case http.StatusOK:
				if resp.Truncated {
					responseTruncated = true
					if pages == 1 {
						degraded = append(degraded, "experiments response truncated at max_response_bytes")
						checks = append(checks, common.CheckEntry{
							CheckID: CheckExperiments, Operation: CheckExperiments, Outcome: graph.OutcomeFailed,
							Reason: "experiments response truncated at max_response_bytes limit", OperationKind: graph.EnumerationOperation,
							Details: map[string]any{"http_status": resp.StatusCode, "truncated": true},
						})
					}
					pageToken = ""
				} else {
					var doc map[string]json.RawMessage
					var eResp experimentsResponse
					if json.Unmarshal(resp.Body, &doc) != nil || json.Unmarshal(resp.Body, &eResp) != nil || !hasExperimentsPayload(doc) {
						if pages == 1 {
							degraded = append(degraded, "invalid JSON response from experiments/search")
							checks = append(checks, common.CheckEntry{
								CheckID: CheckExperiments, Operation: CheckExperiments, Outcome: graph.OutcomeFailed,
								Reason: "invalid JSON response from /api/2.0/mlflow/experiments/search", OperationKind: graph.EnumerationOperation,
								Details: map[string]any{"http_status": resp.StatusCode},
							})
						}
						pageToken = ""
					} else {
						mlflowConfirmed = true
						expSuccess = true
						for _, ex := range eResp.Experiments {
							if len(experiments) >= maxItems {
								expTruncated = true
								break
							}
							experiments = append(experiments, ex)
						}
						if expTruncated {
							pageToken = ""
						} else {
							pageToken = strings.TrimSpace(eResp.NextPageToken)
						}
					}
				}
			case http.StatusUnauthorized, http.StatusForbidden:
				if pages == 1 {
					expDenied = true
					if hasMLflowDenial(resp.Header, resp.Body) {
						mlflowConfirmed = true
						deniedConfirmed = true
					}
					degraded = append(degraded, fmt.Sprintf("experiments denied (HTTP %d)", resp.StatusCode))
					checks = append(checks, common.CheckEntry{
						CheckID: CheckExperiments, Operation: CheckExperiments, Outcome: graph.OutcomeDenied,
						Reason:        fmt.Sprintf("HTTP %d: authentication or authorization required", resp.StatusCode),
						OperationKind: graph.EnumerationOperation,
						Details:       map[string]any{"http_status": resp.StatusCode},
					})
				}
				pageToken = ""
			case http.StatusNotFound:
				if pages == 1 {
					degraded = append(degraded, "experiments endpoint unavailable (HTTP 404)")
					checks = append(checks, common.CheckEntry{
						CheckID: CheckExperiments, Operation: CheckExperiments, Outcome: graph.OutcomeFailed,
						Reason: "HTTP 404 not found (experiments/search unavailable)", OperationKind: graph.EnumerationOperation,
						Details: map[string]any{"http_status": resp.StatusCode},
					})
				}
				pageToken = ""
			case http.StatusTooManyRequests:
				if pages == 1 {
					degraded = append(degraded, "experiments endpoint rate limited (HTTP 429)")
					checks = append(checks, common.CheckEntry{
						CheckID: CheckExperiments, Operation: CheckExperiments, Outcome: graph.OutcomeFailed,
						Reason: "HTTP 429 rate limited", OperationKind: graph.EnumerationOperation,
						Details: map[string]any{"http_status": resp.StatusCode},
					})
				}
				pageToken = ""
			default:
				if pages == 1 {
					degraded = append(degraded, fmt.Sprintf("experiments returned HTTP %d", resp.StatusCode))
					checks = append(checks, common.CheckEntry{
						CheckID: CheckExperiments, Operation: CheckExperiments, Outcome: graph.OutcomeFailed,
						Reason:        fmt.Sprintf("HTTP %d unexpected status", resp.StatusCode),
						OperationKind: graph.EnumerationOperation,
						Details:       map[string]any{"http_status": resp.StatusCode},
					})
				}
				pageToken = ""
			}

			if pageToken == "" {
				break
			}
		}
		if expSuccess {
			checks = append(checks, common.CheckEntry{
				CheckID: CheckExperiments, Operation: CheckExperiments, Outcome: graph.OutcomeSuccess,
				Reason: "MLflow experiments enumerated anonymously", Anonymous: true,
				OperationKind: graph.EnumerationOperation, CountForAccess: true,
				Details: map[string]any{
					"experiment_count": len(experiments),
					"pages":            pages,
					"truncated":        expTruncated,
				},
			})
		}
	}

	// 3. Check: GET /api/2.0/mlflow/registered-models/search (paginated enumeration).
	{
		pageToken := ""
		pages := 0
		for {
			if pages >= maxPages {
				modelsTruncated = true
				break
			}
			u := baseURL + "/api/2.0/mlflow/registered-models/search?max_results=100"
			if pageToken != "" {
				u += "&page_token=" + url.QueryEscape(pageToken)
			}
			resp, reqErr := c.transport.Get(ctx, u)
			common.AbsorbTransport(resp, &tlsInfo, &redirects)

			if common.IsTLSFailure(tlsInfo, c.cfg.Insecure) {
				reason := common.SanitizeError(reqErr)
				if reason == "" {
					reason = "TLS certificate verification failed: " + common.BoundString(tlsInfo.VerificationReason, 200)
				}
				checks = append(checks,
					common.CheckEntry{
						CheckID: CheckRegisteredModels, Operation: CheckRegisteredModels, Outcome: graph.OutcomeFailed,
						Reason: reason, OperationKind: graph.EnumerationOperation,
						Details: map[string]any{"tls_error": common.BoundString(tlsInfo.VerificationReason, 200)},
					},
					common.CheckEntry{CheckID: CheckArtifactsList, Operation: CheckArtifactsList, Outcome: graph.OutcomeSkipped, Reason: "prerequisite failed: TLS verification failed", OperationKind: graph.EnumerationOperation},
					common.CheckEntry{CheckID: CheckArtifactText, Operation: CheckArtifactText, Outcome: graph.OutcomeSkipped, Reason: "prerequisite failed: TLS verification failed", OperationKind: graph.ResourceReadOperation},
				)
				return c.buildFailedResult(target, scope, vantageKey, scanID, obsTime, evID, u, srvID, reason, checks, tlsInfo, redirects)
			}

			if reqErr != nil {
				if pages == 0 {
					modelsErr = reqErr
					reason := common.SanitizeError(reqErr)
					degraded = append(degraded, "registered-models check failed: "+reason)
					checks = append(checks, common.CheckEntry{
						CheckID: CheckRegisteredModels, Operation: CheckRegisteredModels, Outcome: graph.OutcomeFailed,
						Reason: reason, OperationKind: graph.EnumerationOperation,
						Details: map[string]any{"error": reason},
					})
				} else {
					degraded = append(degraded, "registered-models pagination stopped: "+common.SanitizeError(reqErr))
				}
				break
			}

			pages++
			switch resp.StatusCode {
			case http.StatusOK:
				if resp.Truncated {
					responseTruncated = true
					if pages == 1 {
						degraded = append(degraded, "registered-models response truncated at max_response_bytes")
						checks = append(checks, common.CheckEntry{
							CheckID: CheckRegisteredModels, Operation: CheckRegisteredModels, Outcome: graph.OutcomeFailed,
							Reason: "registered-models response truncated at max_response_bytes limit", OperationKind: graph.EnumerationOperation,
							Details: map[string]any{"http_status": resp.StatusCode, "truncated": true},
						})
					}
					pageToken = ""
				} else {
					var doc map[string]json.RawMessage
					var mResp registeredModelsResponse
					if json.Unmarshal(resp.Body, &doc) != nil || json.Unmarshal(resp.Body, &mResp) != nil || !hasRegisteredModelsPayload(doc) {
						if pages == 1 {
							degraded = append(degraded, "invalid JSON response from registered-models/search")
							checks = append(checks, common.CheckEntry{
								CheckID: CheckRegisteredModels, Operation: CheckRegisteredModels, Outcome: graph.OutcomeFailed,
								Reason: "invalid JSON response from /api/2.0/mlflow/registered-models/search", OperationKind: graph.EnumerationOperation,
								Details: map[string]any{"http_status": resp.StatusCode},
							})
						}
						pageToken = ""
					} else {
						mlflowConfirmed = true
						modelsSuccess = true
						for _, rm := range mResp.RegisteredModels {
							if len(regModels) >= maxItems {
								modelsTruncated = true
								break
							}
							regModels = append(regModels, rm)
						}
						if modelsTruncated {
							pageToken = ""
						} else {
							pageToken = strings.TrimSpace(mResp.NextPageToken)
						}
					}
				}
			case http.StatusUnauthorized, http.StatusForbidden:
				if pages == 1 {
					modelsDenied = true
					if hasMLflowDenial(resp.Header, resp.Body) {
						mlflowConfirmed = true
						deniedConfirmed = true
					}
					degraded = append(degraded, fmt.Sprintf("registered-models denied (HTTP %d)", resp.StatusCode))
					checks = append(checks, common.CheckEntry{
						CheckID: CheckRegisteredModels, Operation: CheckRegisteredModels, Outcome: graph.OutcomeDenied,
						Reason:        fmt.Sprintf("HTTP %d: authentication or authorization required", resp.StatusCode),
						OperationKind: graph.EnumerationOperation,
						Details:       map[string]any{"http_status": resp.StatusCode},
					})
				}
				pageToken = ""
			case http.StatusNotFound:
				if pages == 1 {
					degraded = append(degraded, "registered-models endpoint unavailable (HTTP 404)")
					checks = append(checks, common.CheckEntry{
						CheckID: CheckRegisteredModels, Operation: CheckRegisteredModels, Outcome: graph.OutcomeFailed,
						Reason: "HTTP 404 not found (registered-models/search unavailable)", OperationKind: graph.EnumerationOperation,
						Details: map[string]any{"http_status": resp.StatusCode},
					})
				}
				pageToken = ""
			case http.StatusTooManyRequests:
				if pages == 1 {
					degraded = append(degraded, "registered-models rate limited (HTTP 429)")
					checks = append(checks, common.CheckEntry{
						CheckID: CheckRegisteredModels, Operation: CheckRegisteredModels, Outcome: graph.OutcomeFailed,
						Reason: "HTTP 429 rate limited", OperationKind: graph.EnumerationOperation,
						Details: map[string]any{"http_status": resp.StatusCode},
					})
				}
				pageToken = ""
			default:
				if pages == 1 {
					degraded = append(degraded, fmt.Sprintf("registered-models returned HTTP %d", resp.StatusCode))
					checks = append(checks, common.CheckEntry{
						CheckID: CheckRegisteredModels, Operation: CheckRegisteredModels, Outcome: graph.OutcomeFailed,
						Reason:        fmt.Sprintf("HTTP %d unexpected status", resp.StatusCode),
						OperationKind: graph.EnumerationOperation,
						Details:       map[string]any{"http_status": resp.StatusCode},
					})
				}
				pageToken = ""
			}

			if pageToken == "" {
				break
			}
		}
		if modelsSuccess {
			checks = append(checks, common.CheckEntry{
				CheckID: CheckRegisteredModels, Operation: CheckRegisteredModels, Outcome: graph.OutcomeSuccess,
				Reason: "MLflow registered models enumerated anonymously", Anonymous: true,
				OperationKind: graph.EnumerationOperation, CountForAccess: true,
				Details: map[string]any{
					"registered_model_count": len(regModels),
					"pages":                  pages,
					"truncated":              modelsTruncated,
				},
			})
		}
	}

	// Collect unique run IDs from registered model versions for artifact inventory.
	runIDSet := make(map[string]bool)
	var runIDs []string
	for _, rm := range regModels {
		for _, lv := range rm.LatestVersions {
			rid := strings.TrimSpace(lv.RunID)
			if rid != "" && !runIDSet[rid] {
				runIDSet[rid] = true
				runIDs = append(runIDs, rid)
				if len(runIDs) >= maxItems {
					break
				}
			}
		}
		if len(runIDs) >= maxItems {
			break
		}
	}
	sort.Strings(runIDs)

	// 4. Check: GET /api/2.0/mlflow/artifacts/list?run_id=<run_id>.
	var textArtifacts []artifactTarget
	var artifactFilesListed int
	if !mlflowConfirmed {
		checks = append(checks, common.CheckEntry{
			CheckID: CheckArtifactsList, Operation: CheckArtifactsList, Outcome: graph.OutcomeSkipped,
			Reason: "prerequisite failed: MLflow identity not established", OperationKind: graph.EnumerationOperation,
		})
	} else if len(runIDs) == 0 {
		checks = append(checks, common.CheckEntry{
			CheckID: CheckArtifactsList, Operation: CheckArtifactsList, Outcome: graph.OutcomeSkipped,
			Reason: "no run_id entries available from registered models", OperationKind: graph.EnumerationOperation,
		})
	} else {
		listSuccess := 0
		listDenied := 0
		var listErrors []string
		for _, rid := range runIDs {
			listURL := baseURL + "/api/2.0/mlflow/artifacts/list?run_id=" + url.QueryEscape(rid)
			resp, reqErr := c.transport.Get(ctx, listURL)
			common.AbsorbTransport(resp, &tlsInfo, &redirects)
			if reqErr != nil {
				listErrors = append(listErrors, fmt.Sprintf("%s: %s", rid, common.SanitizeError(reqErr)))
				continue
			}
			switch resp.StatusCode {
			case http.StatusOK:
				if resp.Truncated {
					responseTruncated = true
					listErrors = append(listErrors, fmt.Sprintf("%s: truncated at max_response_bytes", rid))
					continue
				}
				var aResp artifactsListResponse
				if err := json.Unmarshal(resp.Body, &aResp); err != nil {
					listErrors = append(listErrors, fmt.Sprintf("%s: invalid JSON", rid))
					continue
				}
				listSuccess++
				for _, f := range aResp.Files {
					if f.IsDir {
						continue
					}
					artifactFilesListed++
					if isAllowlistedTextArtifact(f.Path) {
						textArtifacts = append(textArtifacts, artifactTarget{
							RunID: rid,
							Path:  f.Path,
							Size:  f.FileSize,
						})
					}
				}
			case http.StatusUnauthorized, http.StatusForbidden:
				listDenied++
				listErrors = append(listErrors, fmt.Sprintf("%s: HTTP %d", rid, resp.StatusCode))
			default:
				listErrors = append(listErrors, fmt.Sprintf("%s: HTTP %d", rid, resp.StatusCode))
			}
		}

		switch {
		case listSuccess > 0:
			details := map[string]any{
				"runs_inspected":   listSuccess,
				"artifact_count":   artifactFilesListed,
				"allowlisted_text": len(textArtifacts),
			}
			if len(listErrors) > 0 {
				details["errors"] = listErrors
				degraded = append(degraded, fmt.Sprintf("artifact listing succeeded for %d of %d runs", listSuccess, len(runIDs)))
			}
			checks = append(checks, common.CheckEntry{
				CheckID: CheckArtifactsList, Operation: CheckArtifactsList, Outcome: graph.OutcomeSuccess,
				Reason:        fmt.Sprintf("artifact inventory enumerated for %d of %d runs", listSuccess, len(runIDs)),
				Anonymous:     true,
				OperationKind: graph.EnumerationOperation, CountForAccess: true, Details: details,
			})
		case listDenied > 0 && listDenied == len(runIDs):
			degraded = append(degraded, "artifact listing denied for all runs")
			checks = append(checks, common.CheckEntry{
				CheckID: CheckArtifactsList, Operation: CheckArtifactsList, Outcome: graph.OutcomeDenied,
				Reason: "authentication or authorization required for artifact listing", OperationKind: graph.EnumerationOperation,
				Details: map[string]any{"errors": listErrors},
			})
		default:
			degraded = append(degraded, "artifact listing failed")
			checks = append(checks, common.CheckEntry{
				CheckID: CheckArtifactsList, Operation: CheckArtifactsList, Outcome: graph.OutcomeFailed,
				Reason: "failed to list artifacts: " + strings.Join(listErrors, "; "), OperationKind: graph.EnumerationOperation,
				Details: map[string]any{"errors": listErrors},
			})
		}
	}

	// 5. Check: Bounded Allowlisted Small Text Artifact Reads (content tier).
	var contentSummary *graph.ContentSummary
	var contentTruncated bool
	var contentTruncReasons []string
	if !c.cfg.Content.EnabledFor(Surface) {
		checks = append(checks, common.CheckEntry{
			CheckID: CheckArtifactText, Operation: CheckArtifactText, Outcome: graph.OutcomeSkipped,
			Reason: "content collection disabled by policy", OperationKind: graph.ResourceReadOperation,
			Details: map[string]any{"skipped": true, "policy": "content_disabled"},
		})
	} else if !mlflowConfirmed {
		checks = append(checks, common.CheckEntry{
			CheckID: CheckArtifactText, Operation: CheckArtifactText, Outcome: graph.OutcomeSkipped,
			Reason: "prerequisite failed: MLflow identity not established", OperationKind: graph.ResourceReadOperation,
		})
	} else if len(textArtifacts) == 0 {
		checks = append(checks, common.CheckEntry{
			CheckID: CheckArtifactText, Operation: CheckArtifactText, Outcome: graph.OutcomeSkipped,
			Reason: "no allowlisted small text artifacts found", OperationKind: graph.ResourceReadOperation,
		})
	} else {
		budget := content.NewBudget(c.cfg.Content, secrets.NewRedactor(c.cfg.Secrets))
		textSuccess := 0
		textDenied := 0
		var textErrors []string

		for _, art := range textArtifacts {
			if ok, _ := budget.ClaimResourceItem(art.RunID); !ok {
				continue
			}
			getURL := fmt.Sprintf("%s/get-artifact?path=%s&run_id=%s", baseURL, url.QueryEscape(art.Path), url.QueryEscape(art.RunID))
			resp, reqErr := c.transport.Get(ctx, getURL)
			common.AbsorbTransport(resp, &tlsInfo, &redirects)
			if reqErr != nil {
				textErrors = append(textErrors, fmt.Sprintf("%s/%s: %s", art.RunID, art.Path, common.SanitizeError(reqErr)))
				continue
			}
			if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
				textDenied++
				textErrors = append(textErrors, fmt.Sprintf("%s/%s: HTTP %d", art.RunID, art.Path, resp.StatusCode))
				continue
			}
			if resp.StatusCode != http.StatusOK {
				textErrors = append(textErrors, fmt.Sprintf("%s/%s: HTTP %d", art.RunID, art.Path, resp.StatusCode))
				continue
			}
			if resp.Truncated {
				responseTruncated = true
				budget.MarkTruncated(fmt.Sprintf("artifact %s truncated at max_response_bytes", art.Path))
				textErrors = append(textErrors, fmt.Sprintf("%s/%s: truncated at max_response_bytes", art.RunID, art.Path))
				continue
			}
			if content.LooksBinary(resp.Body) {
				continue
			}
			textSuccess++
			rec, added, addErr := budget.Add(content.RecordInput{
				DeploymentScope: scope,
				ScanID:          scanID,
				VantageKey:      vantageKey,
				ServiceID:       srvID.ID(),
				Surface:         Surface,
				CheckID:         CheckArtifactText,
				Source:          getURL,
				Kind:            content.KindArtifactText,
				Location:        fmt.Sprintf("%s/%s", art.RunID, art.Path),
				MediaType:       mediaTypeForArtifact(art.Path),
				ObservedAt:      obsTime,
				Body:            string(resp.Body),
			})
			if addErr != nil {
				return checkpoint.Result{}, fmt.Errorf("create mlflow artifact content record: %w", addErr)
			}
			if added && c.contentSink != nil {
				if err := c.contentSink.Write(rec); err != nil {
					return checkpoint.Result{}, fmt.Errorf("write mlflow artifact content record: %w", err)
				}
			}
		}

		contentTruncated = budget.Truncated()
		contentTruncReasons = budget.Reasons()
		contentSummary = common.ContentSummaryFromBudget(budget, obsTime, nil, nil)

		switch {
		case textSuccess > 0:
			details := map[string]any{
				"artifacts_read":    textSuccess,
				"content_items":     len(budget.Records()),
				"content_bytes":     budget.Bytes(),
				"content_truncated": contentTruncated,
			}
			if len(textErrors) > 0 {
				details["errors"] = textErrors
				degraded = append(degraded, fmt.Sprintf("text artifact reads succeeded for %d of %d items", textSuccess, len(textArtifacts)))
			}
			if found := budget.Findings(); len(found) > 0 {
				details["detected_exposures"] = content.ExposureDetails(found)
			}
			checks = append(checks, common.CheckEntry{
				CheckID: CheckArtifactText, Operation: CheckArtifactText, Outcome: graph.OutcomeSuccess,
				Reason:        fmt.Sprintf("allowlisted text artifacts captured (%d items)", len(budget.Records())),
				OperationKind: graph.ResourceReadOperation, CountForAccess: false, Details: details,
			})
		case textDenied > 0 && textDenied == len(textArtifacts):
			degraded = append(degraded, "text artifact reads denied")
			checks = append(checks, common.CheckEntry{
				CheckID: CheckArtifactText, Operation: CheckArtifactText, Outcome: graph.OutcomeDenied,
				Reason: "authentication or authorization required for artifact content", OperationKind: graph.ResourceReadOperation,
				Details: map[string]any{"errors": textErrors},
			})
		default:
			degraded = append(degraded, "text artifact reads failed")
			checks = append(checks, common.CheckEntry{
				CheckID: CheckArtifactText, Operation: CheckArtifactText, Outcome: graph.OutcomeFailed,
				Reason: "failed to read allowlisted text artifacts: " + strings.Join(textErrors, "; "), OperationKind: graph.ResourceReadOperation,
				Details: map[string]any{"errors": textErrors},
			})
		}
	}

	// Determine coverage & status.
	var finalCoverage graph.Coverage
	var finalCoverageReason string
	var finalStatus checkpoint.TargetStatus

	allUnreachable := verErr != nil && expErr != nil && modelsErr != nil
	switch {
	case allUnreachable:
		finalCoverage = graph.CoverageFailed
		finalStatus = checkpoint.TargetStatusFailed
		finalCoverageReason = "target unreachable: " + common.SanitizeError(verErr)
	case !mlflowConfirmed:
		finalCoverage = graph.CoverageFailed
		finalStatus = checkpoint.TargetStatusFailed
		finalCoverageReason = "enumeration failed: target not confirmed as MLflow"
	case verSuccess && expSuccess && modelsSuccess:
		if expTruncated || modelsTruncated || responseTruncated || contentTruncated {
			finalCoverage = graph.CoverageTruncated
			finalStatus = checkpoint.TargetStatusPartial
			finalCoverageReason = mlflowTruncationReason(expTruncated, modelsTruncated, responseTruncated, contentTruncReasons)
		} else if len(degraded) > 0 {
			finalCoverage = graph.CoveragePartial
			finalStatus = checkpoint.TargetStatusPartial
			finalCoverageReason = strings.Join(degraded, "; ")
		} else {
			finalCoverage = graph.CoverageComplete
			finalStatus = checkpoint.TargetStatusCompleted
		}
	case expSuccess || modelsSuccess:
		if expTruncated || modelsTruncated || responseTruncated || contentTruncated {
			finalCoverage = graph.CoverageTruncated
			finalStatus = checkpoint.TargetStatusPartial
			finalCoverageReason = mlflowTruncationReason(expTruncated, modelsTruncated, responseTruncated, contentTruncReasons)
		} else {
			finalCoverage = graph.CoveragePartial
			finalStatus = checkpoint.TargetStatusPartial
			if len(degraded) > 0 {
				finalCoverageReason = strings.Join(degraded, "; ")
			} else {
				finalCoverageReason = "partial MLflow metadata enumerated"
			}
		}
	case deniedConfirmed && (verDenied || expDenied || modelsDenied):
		finalCoverage = graph.CoveragePartial
		finalStatus = checkpoint.TargetStatusPartial
		finalCoverageReason = "authentication required on MLflow endpoint"
	default:
		finalCoverage = graph.CoverageFailed
		finalStatus = checkpoint.TargetStatusFailed
		finalCoverageReason = "enumeration failed: target not confirmed as MLflow"
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
		storeSet := make(map[string]bool)
		var storeRefs []string
		addStoreRef := func(raw string) {
			s := sanitizeStoreRef(raw)
			if s == "" || storeSet[s] {
				return
			}
			storeSet[s] = true
			storeRefs = append(storeRefs, s)
		}
		for _, ex := range experiments {
			addStoreRef(ex.ArtifactLocation)
		}
		type versionArtifact struct {
			key     string
			name    string
			version string
			stage   string
			runID   string
			source  string
			aliases []string
		}
		var modelArtifacts []versionArtifact
		artifactSeen := make(map[string]bool)
		var regModelCount int
		for _, rm := range regModels {
			regModelCount++
			aliasByVer := make(map[string][]string)
			for _, al := range rm.Aliases {
				if al.Version != "" && al.Alias != "" {
					aliasByVer[al.Version] = append(aliasByVer[al.Version], al.Alias)
				}
			}
			for _, lv := range rm.LatestVersions {
				name := strings.TrimSpace(lv.Name)
				if name == "" {
					name = strings.TrimSpace(rm.Name)
				}
				ver := strings.TrimSpace(lv.Version)
				if name == "" || ver == "" {
					continue
				}
				addStoreRef(lv.Source)
				key := name + "@" + ver
				if artifactSeen[key] {
					continue
				}
				artifactSeen[key] = true
				aliases := aliasByVer[ver]
				sort.Strings(aliases)
				modelArtifacts = append(modelArtifacts, versionArtifact{
					key:     key,
					name:    name,
					version: ver,
					stage:   common.BoundString(lv.CurrentStage, 64),
					runID:   common.BoundString(lv.RunID, 128),
					source:  sanitizeStoreRef(lv.Source),
					aliases: aliases,
				})
			}
		}
		sort.Strings(storeRefs)

		access := common.SummarizeAccess(srvID.ID(), obs, checks)
		facts := graph.ServiceFacts{
			Endpoint:         ep,
			Name:             fmt.Sprintf("MLflow · %s:%d", ep.Host(), ep.Port()),
			Product:          "MLflow",
			Vendor:           "Linux Foundation",
			VantageKey:       vantageKey,
			Access:           access,
			ExecSurface:      []string{graph.ExecModelMutation},
			ExecSurfaceBasis: graph.BasisInferred,
			StoreRefs:        storeRefs,
			BackendRefsBasis: graph.BasisDeclared,
			TLS:              common.TLSSummary(tlsInfo),
			Content:          contentSummary,
		}
		if modelsSuccess {
			facts.ModelCount = common.IntPtr(regModelCount)
		}
		srvProps := facts.Properties()
		if normVersion != "" {
			srvProps["software_version"] = normVersion
		}
		if rawVersion != "" {
			srvProps["software_version_raw"] = rawVersion
		}
		if expSuccess {
			srvProps["experiment_count"] = len(experiments)
		}

		srvNode, err := graph.NewNode(srvID, obs)
		if err != nil {
			return checkpoint.Result{}, fmt.Errorf("create MLflowServer node: %w", err)
		}
		srvItem, err := emitter.NewNodeItem(srvNode, srvProps)
		if err != nil {
			return checkpoint.Result{}, fmt.Errorf("create MLflowServer node item: %w", err)
		}
		nodes = append(nodes, srvItem)

		for _, ma := range modelArtifacts {
			maID, err := graph.NewResourceIdentity(scope, graph.ModelArtifact, srvID, ma.key)
			if err != nil {
				continue
			}
			maNode, err := graph.NewNode(maID, obs)
			if err != nil {
				continue
			}
			maProps := map[string]any{
				"name":          ma.key,
				"model_name":    ma.name,
				"model_version": ma.version,
			}
			if ma.stage != "" {
				maProps["stage"] = ma.stage
			}
			if ma.runID != "" {
				maProps["run_id"] = ma.runID
			}
			if ma.source != "" {
				maProps["source"] = ma.source
			}
			if len(ma.aliases) > 0 {
				maProps["aliases"] = ma.aliases
			}
			maItem, err := emitter.NewNodeItem(maNode, maProps)
			if err != nil {
				continue
			}
			cEdge, err := graph.NewTopologyEdge(graph.Contains, srvID.Reference(), maID.Reference(), obs)
			if err != nil {
				continue
			}
			nodes = append(nodes, maItem)
			edges = append(edges, cEdge)
		}

		for _, sRef := range storeRefs {
			stID, err := graph.NewResourceIdentity(scope, graph.ArtifactStore, srvID, sRef)
			if err != nil {
				continue
			}
			stNode, err := graph.NewNode(stID, obs)
			if err != nil {
				continue
			}
			stItem, err := emitter.NewNodeItem(stNode, map[string]any{
				"name":      sRef,
				"store_uri": sRef,
			})
			if err != nil {
				continue
			}
			cEdge, err := graph.NewTopologyEdge(graph.Contains, srvID.Reference(), stID.Reference(), obs)
			if err != nil {
				continue
			}
			nodes = append(nodes, stItem)
			edges = append(edges, cEdge)
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

		method := CheckExperiments
		confidence := "exact"
		if verSuccess {
			method = CheckVersion
		} else if !expSuccess && !modelsSuccess {
			method = "denied_response"
			confidence = "inferred"
		}
		fpInput = &evidence.FingerprintInput{
			TargetID:           srvID.ID(),
			Product:            "MLflow",
			Vendor:             "Linux Foundation",
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

func parseMLflowVersionBody(h http.Header, body []byte) (string, bool) {
	ct := strings.ToLower(h.Get("Content-Type"))
	if strings.Contains(ct, "text/html") {
		return "", false
	}
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" || len(trimmed) > 64 || strings.HasPrefix(trimmed, "<") || strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		return "", false
	}
	if common.NormalizeVersion(trimmed) == "" {
		return "", false
	}
	return trimmed, true
}

func hasExperimentsPayload(doc map[string]json.RawMessage) bool {
	raw, ok := doc["experiments"]
	if !ok {
		return false
	}
	return strings.HasPrefix(strings.TrimSpace(string(raw)), "[")
}

func hasRegisteredModelsPayload(doc map[string]json.RawMessage) bool {
	raw, ok := doc["registered_models"]
	if !ok {
		return false
	}
	return strings.HasPrefix(strings.TrimSpace(string(raw)), "[")
}

func hasMLflowDenial(h http.Header, body []byte) bool {
	b := strings.ToLower(string(body))
	www := strings.ToLower(h.Get("Www-Authenticate"))
	return strings.Contains(b, "mlflow") || strings.Contains(www, "mlflow")
}

func sanitizeStoreRef(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || strings.ContainsFunc(trimmed, unicode.IsControl) {
		return ""
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "http", "https":
		return common.SanitizeHTTPReference(trimmed)
	case "s3", "s3a", "gs", "abfs", "abfss", "wasb", "wasbs", "hdfs", "dbfs", "file", "mlflow-artifacts":
		u.Scheme = scheme
		u.User = nil
		u.RawQuery = ""
		u.ForceQuery = false
		u.Fragment = ""
		return common.BoundString(u.String(), 512)
	default:
		return ""
	}
}

func isAllowlistedTextArtifact(p string) bool {
	clean := strings.TrimSpace(p)
	if clean == "" {
		return false
	}
	base := strings.ToLower(path.Base(clean))
	ext := strings.ToLower(path.Ext(base))
	if blockedWeightExtensions[ext] {
		return false
	}
	return allowlistedTextArtifacts[base]
}

func mediaTypeForArtifact(p string) string {
	switch strings.ToLower(path.Ext(p)) {
	case ".json":
		return "application/json"
	case ".yaml", ".yml":
		return "application/yaml"
	default:
		return "text/plain"
	}
}

func mlflowTruncationReason(expTrunc, modelsTrunc, respTrunc bool, contentReasons []string) string {
	var parts []string
	if expTrunc {
		parts = append(parts, "experiments listing truncated at max_items/max_pages bound")
	}
	if modelsTrunc {
		parts = append(parts, "registered models listing truncated at max_items/max_pages bound")
	}
	if respTrunc {
		parts = append(parts, "response body truncated at max_response_bytes bound")
	}
	parts = append(parts, contentReasons...)
	return strings.Join(parts, "; ")
}
