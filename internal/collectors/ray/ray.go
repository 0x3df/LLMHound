// Package ray provides anonymous, read-only metadata enumeration of Ray
// Dashboard endpoints (/api/version, /api/cluster_status, /api/jobs/,
// /api/v0/actors) and bounded job entrypoint/env content capture without ever
// submitting or stopping jobs.
package ray

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
	// Surface is the canonical surface identifier for Ray Dashboard.
	Surface = "ray"

	// DefaultPort is the default listener port for Ray Dashboard.
	DefaultPort = 8265

	// Allowlisted check identifiers.
	CheckVersion       = "ray_version"
	CheckClusterStatus = "ray_cluster_status"
	CheckJobs          = "ray_jobs"
	CheckActors        = "ray_actors"
	CheckJobContent    = "ray_job_content"
)

type versionResponse struct {
	Version    string `json:"version"`
	RayVersion string `json:"ray_version"`
	RayCommit  string `json:"ray_commit"`
}

type clusterStatusResponse struct {
	Result bool `json:"result"`
	Data   struct {
		AutoscalingStatus json.RawMessage `json:"autoscalingStatus,omitempty"`
		ClusterStatus     *struct {
			ActiveNodes map[string]int `json:"active_nodes,omitempty"`
			Nodes       []any          `json:"nodes,omitempty"`
		} `json:"clusterStatus,omitempty"`
		LoadMetricsReport *struct {
			UsageByNode map[string]any `json:"usageByNode,omitempty"`
		} `json:"loadMetricsReport,omitempty"`
	} `json:"data"`
}

type jobEntry struct {
	SubmissionID string          `json:"submission_id"`
	JobID        string          `json:"job_id"`
	Status       string          `json:"status"`
	Type         string          `json:"type"`
	Entrypoint   string          `json:"entrypoint"`
	RuntimeEnv   json.RawMessage `json:"runtime_env,omitempty"`
}

type actorsResponse struct {
	Result bool `json:"result"`
	Data   struct {
		Result *struct {
			Total  *int            `json:"total,omitempty"`
			Result json.RawMessage `json:"result,omitempty"`
		} `json:"result,omitempty"`
		Actors map[string]json.RawMessage `json:"actors,omitempty"`
	} `json:"data"`
}

// Collector implements anonymous, read-only Ray Dashboard enumeration.
type Collector struct {
	cfg         config.Config
	transport   *transport.Client
	contentSink content.Sink
}

// Option configures a Ray Collector.
type Option func(*Collector)

// WithTransport overrides the transport client (primarily for testing).
func WithTransport(tc *transport.Client) Option {
	return func(c *Collector) {
		c.transport = tc
	}
}

// WithContentSink configures where bounded job entrypoint/runtime_env bodies are written.
func WithContentSink(sink content.Sink) Option {
	return func(c *Collector) {
		c.contentSink = sink
	}
}

// New constructs a Ray collector with the given configuration.
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

// Collect performs allowlisted GET metadata checks and optional bounded job
// entrypoint/env content capture on a Ray Dashboard without submitting jobs.
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

	srvID, err := graph.NewServiceIdentity(scope, graph.RayDashboard, ep)
	if err != nil {
		return checkpoint.Result{}, fmt.Errorf("create service identity: %w", err)
	}

	evID := common.EvidenceID(scanID, srvID.ID(), obsTime)
	baseURL := strings.TrimSuffix(ep.String(), "/")
	sourceURL := baseURL + "/api/jobs/"

	var tlsInfo *transport.TLSInfo
	var redirects []transport.RedirectInfo
	var checks []common.CheckEntry
	var degraded []string

	var rayConfirmed bool
	var deniedConfirmed bool
	var rawVersion, normVersion, apiVersion, commit string
	var verSuccess, verDenied bool
	var verErr error

	var clusterSuccess, clusterDenied bool
	var clusterErr error
	var nodeCount *int

	var jobs []jobEntry
	var jobsSuccess, jobsDenied, jobsTruncated bool
	var jobsErr error

	var actorsSuccess, actorsDenied bool
	var actorCount *int
	var responseTruncated bool

	maxItems := c.cfg.Bounds.MaxItems
	if maxItems <= 0 {
		maxItems = 10000
	}

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
				common.CheckEntry{CheckID: CheckClusterStatus, Operation: CheckClusterStatus, Outcome: graph.OutcomeSkipped, Reason: "prerequisite failed: TLS verification failed", OperationKind: graph.EnumerationOperation},
				common.CheckEntry{CheckID: CheckJobs, Operation: CheckJobs, Outcome: graph.OutcomeSkipped, Reason: "prerequisite failed: TLS verification failed", OperationKind: graph.EnumerationOperation},
				common.CheckEntry{CheckID: CheckActors, Operation: CheckActors, Outcome: graph.OutcomeSkipped, Reason: "prerequisite failed: TLS verification failed", OperationKind: graph.EnumerationOperation},
				common.CheckEntry{CheckID: CheckJobContent, Operation: CheckJobContent, Outcome: graph.OutcomeSkipped, Reason: "prerequisite failed: TLS verification failed", OperationKind: graph.ResourceReadOperation},
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
					if err := json.Unmarshal(resp.Body, &v); err != nil || (strings.TrimSpace(v.RayVersion) == "" && strings.TrimSpace(v.RayCommit) == "") {
						degraded = append(degraded, "response from /api/version lacks Ray version fields")
						checks = append(checks, common.CheckEntry{
							CheckID: CheckVersion, Operation: CheckVersion, Outcome: graph.OutcomeFailed,
							Reason: "invalid JSON or missing ray_version/ray_commit in /api/version", OperationKind: graph.EnumerationOperation,
							Details: map[string]any{"http_status": resp.StatusCode},
						})
					} else {
						rayConfirmed = true
						verSuccess = true
						rawVersion = common.BoundString(v.RayVersion, 128)
						normVersion = common.NormalizeVersion(v.RayVersion)
						apiVersion = common.BoundString(v.Version, 64)
						commit = common.BoundString(v.RayCommit, 128)
						checks = append(checks, common.CheckEntry{
							CheckID: CheckVersion, Operation: CheckVersion, Outcome: graph.OutcomeSuccess,
							Reason: fmt.Sprintf("Ray version reported: %s", rawVersion), Anonymous: true,
							OperationKind: graph.EnumerationOperation, CountForAccess: false,
							Details: map[string]any{
								"http_status":          resp.StatusCode,
								"software_version":     normVersion,
								"software_version_raw": rawVersion,
								"api_version":          apiVersion,
								"commit":               commit,
							},
						})
					}
				}
			case http.StatusUnauthorized, http.StatusForbidden:
				verDenied = true
				if hasRayDenial(resp.Header, resp.Body) {
					rayConfirmed = true
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

	// 2. Check: GET /api/cluster_status (enumeration check).
	{
		resp, reqErr := c.transport.Get(ctx, baseURL+"/api/cluster_status")
		common.AbsorbTransport(resp, &tlsInfo, &redirects)

		if common.IsTLSFailure(tlsInfo, c.cfg.Insecure) {
			reason := common.SanitizeError(reqErr)
			if reason == "" {
				reason = "TLS certificate verification failed: " + common.BoundString(tlsInfo.VerificationReason, 200)
			}
			checks = append(checks,
				common.CheckEntry{
					CheckID: CheckClusterStatus, Operation: CheckClusterStatus, Outcome: graph.OutcomeFailed,
					Reason: reason, OperationKind: graph.EnumerationOperation,
					Details: map[string]any{"tls_error": common.BoundString(tlsInfo.VerificationReason, 200)},
				},
				common.CheckEntry{CheckID: CheckJobs, Operation: CheckJobs, Outcome: graph.OutcomeSkipped, Reason: "prerequisite failed: TLS verification failed", OperationKind: graph.EnumerationOperation},
				common.CheckEntry{CheckID: CheckActors, Operation: CheckActors, Outcome: graph.OutcomeSkipped, Reason: "prerequisite failed: TLS verification failed", OperationKind: graph.EnumerationOperation},
				common.CheckEntry{CheckID: CheckJobContent, Operation: CheckJobContent, Outcome: graph.OutcomeSkipped, Reason: "prerequisite failed: TLS verification failed", OperationKind: graph.ResourceReadOperation},
			)
			return c.buildFailedResult(target, scope, vantageKey, scanID, obsTime, evID, baseURL+"/api/cluster_status", srvID, reason, checks, tlsInfo, redirects)
		}

		if reqErr != nil {
			clusterErr = reqErr
			reason := common.SanitizeError(reqErr)
			degraded = append(degraded, "cluster_status check failed: "+reason)
			checks = append(checks, common.CheckEntry{
				CheckID: CheckClusterStatus, Operation: CheckClusterStatus, Outcome: graph.OutcomeFailed,
				Reason: reason, OperationKind: graph.EnumerationOperation,
				Details: map[string]any{"error": reason},
			})
		} else {
			switch resp.StatusCode {
			case http.StatusOK:
				if resp.Truncated {
					responseTruncated = true
					degraded = append(degraded, "cluster_status truncated at max_response_bytes")
					checks = append(checks, common.CheckEntry{
						CheckID: CheckClusterStatus, Operation: CheckClusterStatus, Outcome: graph.OutcomeFailed,
						Reason: "cluster_status truncated at max_response_bytes limit", OperationKind: graph.EnumerationOperation,
						Details: map[string]any{"http_status": resp.StatusCode, "truncated": true},
					})
				} else {
					var cs clusterStatusResponse
					if err := json.Unmarshal(resp.Body, &cs); err != nil || (!cs.Result && cs.Data.ClusterStatus == nil && cs.Data.LoadMetricsReport == nil) {
						degraded = append(degraded, "invalid JSON in /api/cluster_status")
						checks = append(checks, common.CheckEntry{
							CheckID: CheckClusterStatus, Operation: CheckClusterStatus, Outcome: graph.OutcomeFailed,
							Reason: "invalid JSON response from /api/cluster_status", OperationKind: graph.EnumerationOperation,
							Details: map[string]any{"http_status": resp.StatusCode},
						})
					} else {
						rayConfirmed = true
						clusterSuccess = true
						nodeCount = extractClusterNodeCount(cs)
						details := map[string]any{"http_status": resp.StatusCode}
						if nodeCount != nil {
							details["node_count"] = *nodeCount
						}
						checks = append(checks, common.CheckEntry{
							CheckID: CheckClusterStatus, Operation: CheckClusterStatus, Outcome: graph.OutcomeSuccess,
							Reason: "Ray cluster status enumerated anonymously", Anonymous: true,
							OperationKind: graph.EnumerationOperation, CountForAccess: true, Details: details,
						})
					}
				}
			case http.StatusUnauthorized, http.StatusForbidden:
				clusterDenied = true
				if hasRayDenial(resp.Header, resp.Body) {
					rayConfirmed = true
					deniedConfirmed = true
				}
				degraded = append(degraded, fmt.Sprintf("cluster_status denied (HTTP %d)", resp.StatusCode))
				checks = append(checks, common.CheckEntry{
					CheckID: CheckClusterStatus, Operation: CheckClusterStatus, Outcome: graph.OutcomeDenied,
					Reason:        fmt.Sprintf("HTTP %d: authentication or authorization required", resp.StatusCode),
					OperationKind: graph.EnumerationOperation,
					Details:       map[string]any{"http_status": resp.StatusCode},
				})
			case http.StatusNotFound:
				degraded = append(degraded, "cluster_status unavailable (HTTP 404)")
				checks = append(checks, common.CheckEntry{
					CheckID: CheckClusterStatus, Operation: CheckClusterStatus, Outcome: graph.OutcomeFailed,
					Reason: "HTTP 404 not found (/api/cluster_status unavailable)", OperationKind: graph.EnumerationOperation,
					Details: map[string]any{"http_status": resp.StatusCode},
				})
			case http.StatusTooManyRequests:
				degraded = append(degraded, "cluster_status rate limited (HTTP 429)")
				checks = append(checks, common.CheckEntry{
					CheckID: CheckClusterStatus, Operation: CheckClusterStatus, Outcome: graph.OutcomeFailed,
					Reason: "HTTP 429 rate limited", OperationKind: graph.EnumerationOperation,
					Details: map[string]any{"http_status": resp.StatusCode},
				})
			default:
				degraded = append(degraded, fmt.Sprintf("cluster_status returned HTTP %d", resp.StatusCode))
				checks = append(checks, common.CheckEntry{
					CheckID: CheckClusterStatus, Operation: CheckClusterStatus, Outcome: graph.OutcomeFailed,
					Reason:        fmt.Sprintf("HTTP %d unexpected status", resp.StatusCode),
					OperationKind: graph.EnumerationOperation,
					Details:       map[string]any{"http_status": resp.StatusCode},
				})
			}
		}
	}

	// 3. Check: GET /api/jobs/ (enumeration check; also evidence for D7 ray-anonymous-jobs).
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
					CheckID: CheckJobs, Operation: CheckJobs, Outcome: graph.OutcomeFailed,
					Reason: reason, OperationKind: graph.EnumerationOperation,
					Details: map[string]any{"tls_error": common.BoundString(tlsInfo.VerificationReason, 200)},
				},
				common.CheckEntry{CheckID: CheckActors, Operation: CheckActors, Outcome: graph.OutcomeSkipped, Reason: "prerequisite failed: TLS verification failed", OperationKind: graph.EnumerationOperation},
				common.CheckEntry{CheckID: CheckJobContent, Operation: CheckJobContent, Outcome: graph.OutcomeSkipped, Reason: "prerequisite failed: TLS verification failed", OperationKind: graph.ResourceReadOperation},
			)
			return c.buildFailedResult(target, scope, vantageKey, scanID, obsTime, evID, sourceURL, srvID, reason, checks, tlsInfo, redirects)
		}

		if reqErr != nil {
			jobsErr = reqErr
			reason := common.SanitizeError(reqErr)
			degraded = append(degraded, "jobs check failed: "+reason)
			checks = append(checks, common.CheckEntry{
				CheckID: CheckJobs, Operation: CheckJobs, Outcome: graph.OutcomeFailed,
				Reason: reason, OperationKind: graph.EnumerationOperation,
				Details: map[string]any{"error": reason},
			})
		} else {
			switch resp.StatusCode {
			case http.StatusOK:
				if resp.Truncated {
					responseTruncated = true
					degraded = append(degraded, "jobs response truncated at max_response_bytes")
					checks = append(checks, common.CheckEntry{
						CheckID: CheckJobs, Operation: CheckJobs, Outcome: graph.OutcomeFailed,
						Reason: "jobs response truncated at max_response_bytes limit", OperationKind: graph.EnumerationOperation,
						Details: map[string]any{"http_status": resp.StatusCode, "truncated": true},
					})
				} else {
					var parsed []jobEntry
					if err := json.Unmarshal(resp.Body, &parsed); err != nil || parsed == nil {
						degraded = append(degraded, "invalid JSON array from /api/jobs/")
						checks = append(checks, common.CheckEntry{
							CheckID: CheckJobs, Operation: CheckJobs, Outcome: graph.OutcomeFailed,
							Reason: "invalid JSON array response from /api/jobs/", OperationKind: graph.EnumerationOperation,
							Details: map[string]any{"http_status": resp.StatusCode},
						})
					} else if !rayConfirmed && !hasRayJobsEvidence(parsed) {
						degraded = append(degraded, "jobs array lacks Ray identity evidence")
						checks = append(checks, common.CheckEntry{
							CheckID: CheckJobs, Operation: CheckJobs, Outcome: graph.OutcomeFailed,
							Reason: "jobs array does not confirm Ray Dashboard", OperationKind: graph.EnumerationOperation,
							Details: map[string]any{"http_status": resp.StatusCode},
						})
					} else {
						rayConfirmed = true
						jobsSuccess = true
						if len(parsed) > maxItems {
							jobsTruncated = true
							jobs = parsed[:maxItems]
						} else {
							jobs = parsed
						}
						checks = append(checks, common.CheckEntry{
							CheckID: CheckJobs, Operation: CheckJobs, Outcome: graph.OutcomeSuccess,
							Reason: "Ray jobs listed anonymously", Anonymous: true,
							OperationKind: graph.EnumerationOperation, CountForAccess: true,
							Details: map[string]any{
								"http_status": resp.StatusCode,
								"job_count":   len(jobs),
								"truncated":   jobsTruncated,
							},
						})
					}
				}
			case http.StatusUnauthorized, http.StatusForbidden:
				jobsDenied = true
				if hasRayDenial(resp.Header, resp.Body) {
					rayConfirmed = true
					deniedConfirmed = true
				}
				degraded = append(degraded, fmt.Sprintf("jobs denied (HTTP %d)", resp.StatusCode))
				checks = append(checks, common.CheckEntry{
					CheckID: CheckJobs, Operation: CheckJobs, Outcome: graph.OutcomeDenied,
					Reason:        fmt.Sprintf("HTTP %d: authentication or authorization required", resp.StatusCode),
					OperationKind: graph.EnumerationOperation,
					Details:       map[string]any{"http_status": resp.StatusCode},
				})
			case http.StatusNotFound:
				degraded = append(degraded, "jobs endpoint unavailable (HTTP 404)")
				checks = append(checks, common.CheckEntry{
					CheckID: CheckJobs, Operation: CheckJobs, Outcome: graph.OutcomeFailed,
					Reason: "HTTP 404 not found (/api/jobs/ unavailable)", OperationKind: graph.EnumerationOperation,
					Details: map[string]any{"http_status": resp.StatusCode},
				})
			case http.StatusTooManyRequests:
				degraded = append(degraded, "jobs rate limited (HTTP 429)")
				checks = append(checks, common.CheckEntry{
					CheckID: CheckJobs, Operation: CheckJobs, Outcome: graph.OutcomeFailed,
					Reason: "HTTP 429 rate limited", OperationKind: graph.EnumerationOperation,
					Details: map[string]any{"http_status": resp.StatusCode},
				})
			default:
				degraded = append(degraded, fmt.Sprintf("jobs returned HTTP %d", resp.StatusCode))
				checks = append(checks, common.CheckEntry{
					CheckID: CheckJobs, Operation: CheckJobs, Outcome: graph.OutcomeFailed,
					Reason:        fmt.Sprintf("HTTP %d unexpected status", resp.StatusCode),
					OperationKind: graph.EnumerationOperation,
					Details:       map[string]any{"http_status": resp.StatusCode},
				})
			}
		}
	}

	// 4. Check: GET /api/v0/actors (enumeration check).
	if !rayConfirmed {
		checks = append(checks, common.CheckEntry{
			CheckID: CheckActors, Operation: CheckActors, Outcome: graph.OutcomeSkipped,
			Reason: "prerequisite failed: Ray Dashboard identity not established", OperationKind: graph.EnumerationOperation,
		})
	} else {
		resp, reqErr := c.transport.Get(ctx, baseURL+"/api/v0/actors")
		common.AbsorbTransport(resp, &tlsInfo, &redirects)
		if reqErr != nil {
			reason := common.SanitizeError(reqErr)
			degraded = append(degraded, "actors check failed: "+reason)
			checks = append(checks, common.CheckEntry{
				CheckID: CheckActors, Operation: CheckActors, Outcome: graph.OutcomeFailed,
				Reason: reason, OperationKind: graph.EnumerationOperation,
				Details: map[string]any{"error": reason},
			})
		} else {
			switch resp.StatusCode {
			case http.StatusOK:
				if resp.Truncated {
					responseTruncated = true
					degraded = append(degraded, "actors response truncated at max_response_bytes")
					checks = append(checks, common.CheckEntry{
						CheckID: CheckActors, Operation: CheckActors, Outcome: graph.OutcomeFailed,
						Reason: "actors response truncated at max_response_bytes limit", OperationKind: graph.EnumerationOperation,
						Details: map[string]any{"http_status": resp.StatusCode, "truncated": true},
					})
				} else {
					var aResp actorsResponse
					if err := json.Unmarshal(resp.Body, &aResp); err != nil {
						degraded = append(degraded, "invalid JSON in /api/v0/actors")
						checks = append(checks, common.CheckEntry{
							CheckID: CheckActors, Operation: CheckActors, Outcome: graph.OutcomeFailed,
							Reason: "invalid JSON response from /api/v0/actors", OperationKind: graph.EnumerationOperation,
							Details: map[string]any{"http_status": resp.StatusCode},
						})
					} else {
						actorsSuccess = true
						actorCount = extractActorCount(aResp)
						details := map[string]any{"http_status": resp.StatusCode}
						if actorCount != nil {
							details["actor_count"] = *actorCount
						}
						checks = append(checks, common.CheckEntry{
							CheckID: CheckActors, Operation: CheckActors, Outcome: graph.OutcomeSuccess,
							Reason: "Ray actors listed anonymously", Anonymous: true,
							OperationKind: graph.EnumerationOperation, CountForAccess: true, Details: details,
						})
					}
				}
			case http.StatusUnauthorized, http.StatusForbidden:
				actorsDenied = true
				degraded = append(degraded, fmt.Sprintf("actors denied (HTTP %d)", resp.StatusCode))
				checks = append(checks, common.CheckEntry{
					CheckID: CheckActors, Operation: CheckActors, Outcome: graph.OutcomeDenied,
					Reason:        fmt.Sprintf("HTTP %d: authentication or authorization required", resp.StatusCode),
					OperationKind: graph.EnumerationOperation,
					Details:       map[string]any{"http_status": resp.StatusCode},
				})
			case http.StatusNotFound:
				degraded = append(degraded, "actors endpoint unavailable (HTTP 404)")
				checks = append(checks, common.CheckEntry{
					CheckID: CheckActors, Operation: CheckActors, Outcome: graph.OutcomeFailed,
					Reason: "HTTP 404 not found (/api/v0/actors unavailable)", OperationKind: graph.EnumerationOperation,
					Details: map[string]any{"http_status": resp.StatusCode},
				})
			default:
				degraded = append(degraded, fmt.Sprintf("actors returned HTTP %d", resp.StatusCode))
				checks = append(checks, common.CheckEntry{
					CheckID: CheckActors, Operation: CheckActors, Outcome: graph.OutcomeFailed,
					Reason:        fmt.Sprintf("HTTP %d unexpected status", resp.StatusCode),
					OperationKind: graph.EnumerationOperation,
					Details:       map[string]any{"http_status": resp.StatusCode},
				})
			}
		}
	}

	// 5. Check: Bounded Job Entrypoint & Runtime Env Content Capture.
	var contentSummary *graph.ContentSummary
	var contentTruncated bool
	var contentTruncReasons []string
	if !c.cfg.Content.EnabledFor(Surface) {
		checks = append(checks, common.CheckEntry{
			CheckID: CheckJobContent, Operation: CheckJobContent, Outcome: graph.OutcomeSkipped,
			Reason: "content collection disabled by policy", OperationKind: graph.ResourceReadOperation,
			Details: map[string]any{"skipped": true, "policy": "content_disabled"},
		})
	} else if !jobsSuccess {
		checks = append(checks, common.CheckEntry{
			CheckID: CheckJobContent, Operation: CheckJobContent, Outcome: graph.OutcomeSkipped,
			Reason: "prerequisite failed: jobs listing unavailable", OperationKind: graph.ResourceReadOperation,
		})
	} else {
		budget := content.NewBudget(c.cfg.Content, secrets.NewRedactor(c.cfg.Secrets))
		captured := 0
		for idx, j := range jobs {
			if strings.TrimSpace(j.Entrypoint) == "" && len(j.RuntimeEnv) == 0 {
				continue
			}
			if ok, _ := budget.ClaimResourceItem("jobs"); !ok {
				break
			}
			jobPayload, _ := json.Marshal(struct {
				SubmissionID string          `json:"submission_id,omitempty"`
				Entrypoint   string          `json:"entrypoint,omitempty"`
				RuntimeEnv   json.RawMessage `json:"runtime_env,omitempty"`
			}{
				SubmissionID: j.SubmissionID,
				Entrypoint:   j.Entrypoint,
				RuntimeEnv:   j.RuntimeEnv,
			})
			if content.LooksBinary(jobPayload) {
				continue
			}
			loc := j.SubmissionID
			if loc == "" {
				loc = j.JobID
			}
			if loc == "" {
				loc = fmt.Sprintf("job-%d", idx)
			}
			rec, added, addErr := budget.Add(content.RecordInput{
				DeploymentScope: scope,
				ScanID:          scanID,
				VantageKey:      vantageKey,
				ServiceID:       srvID.ID(),
				Surface:         Surface,
				CheckID:         CheckJobContent,
				Source:          sourceURL,
				Kind:            content.KindConfig,
				Location:        loc,
				MediaType:       "application/json",
				ObservedAt:      obsTime,
				Body:            string(jobPayload),
			})
			if addErr != nil {
				return checkpoint.Result{}, fmt.Errorf("create ray job content record: %w", addErr)
			}
			if added {
				captured++
				if c.contentSink != nil {
					if err := c.contentSink.Write(rec); err != nil {
						return checkpoint.Result{}, fmt.Errorf("write ray job content record: %w", err)
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
				"jobs_captured":     captured,
				"content_items":     len(budget.Records()),
				"content_bytes":     budget.Bytes(),
				"content_truncated": contentTruncated,
			}
			if found := budget.Findings(); len(found) > 0 {
				details["detected_exposures"] = content.ExposureDetails(found)
			}
			checks = append(checks, common.CheckEntry{
				CheckID: CheckJobContent, Operation: CheckJobContent, Outcome: graph.OutcomeSuccess,
				Reason:        fmt.Sprintf("bounded Ray job entrypoints/env captured (%d items)", captured),
				OperationKind: graph.ResourceReadOperation, CountForAccess: false, Details: details,
			})
		} else {
			checks = append(checks, common.CheckEntry{
				CheckID: CheckJobContent, Operation: CheckJobContent, Outcome: graph.OutcomeSkipped,
				Reason: "no job entrypoints or runtime_env payloads present", OperationKind: graph.ResourceReadOperation,
			})
		}
	}

	var finalCoverage graph.Coverage
	var finalCoverageReason string
	var finalStatus checkpoint.TargetStatus

	allUnreachable := verErr != nil && clusterErr != nil && jobsErr != nil
	switch {
	case allUnreachable:
		finalCoverage = graph.CoverageFailed
		finalStatus = checkpoint.TargetStatusFailed
		finalCoverageReason = "target unreachable: " + common.SanitizeError(verErr)
	case !rayConfirmed:
		finalCoverage = graph.CoverageFailed
		finalStatus = checkpoint.TargetStatusFailed
		finalCoverageReason = "enumeration failed: target not confirmed as Ray Dashboard"
	case verSuccess && jobsSuccess && clusterSuccess && actorsSuccess:
		if jobsTruncated || responseTruncated || contentTruncated {
			finalCoverage = graph.CoverageTruncated
			finalStatus = checkpoint.TargetStatusPartial
			finalCoverageReason = rayTruncationReason(jobsTruncated, responseTruncated, contentTruncReasons)
		} else {
			finalCoverage = graph.CoverageComplete
			finalStatus = checkpoint.TargetStatusCompleted
		}
	case jobsSuccess || clusterSuccess || actorsSuccess || verSuccess:
		if jobsTruncated || responseTruncated || contentTruncated {
			finalCoverage = graph.CoverageTruncated
			finalStatus = checkpoint.TargetStatusPartial
			finalCoverageReason = rayTruncationReason(jobsTruncated, responseTruncated, contentTruncReasons)
		} else {
			finalCoverage = graph.CoveragePartial
			finalStatus = checkpoint.TargetStatusPartial
			if len(degraded) > 0 {
				finalCoverageReason = strings.Join(degraded, "; ")
			} else {
				finalCoverageReason = "partial Ray Dashboard metadata collected"
			}
		}
	case deniedConfirmed && (verDenied || clusterDenied || jobsDenied || actorsDenied):
		finalCoverage = graph.CoveragePartial
		finalStatus = checkpoint.TargetStatusPartial
		finalCoverageReason = "authentication required on Ray Dashboard endpoint"
	default:
		finalCoverage = graph.CoverageFailed
		finalStatus = checkpoint.TargetStatusFailed
		finalCoverageReason = "enumeration failed: target not confirmed as Ray Dashboard"
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
			Name:             fmt.Sprintf("Ray Dashboard · %s:%d", ep.Host(), ep.Port()),
			Product:          "Ray Dashboard",
			Vendor:           "Anyscale",
			Commit:           commit,
			VantageKey:       vantageKey,
			Access:           access,
			ExecSurface:      []string{graph.ExecJobSubmit},
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
		if apiVersion != "" {
			srvProps["api_version"] = apiVersion
		}
		if nodeCount != nil {
			srvProps["node_count"] = *nodeCount
		}
		if jobsSuccess {
			srvProps["job_count"] = len(jobs)
		}
		if actorCount != nil {
			srvProps["actor_count"] = *actorCount
		}

		srvNode, err := graph.NewNode(srvID, obs)
		if err != nil {
			return checkpoint.Result{}, fmt.Errorf("create RayDashboard node: %w", err)
		}
		srvItem, err := emitter.NewNodeItem(srvNode, srvProps)
		if err != nil {
			return checkpoint.Result{}, fmt.Errorf("create RayDashboard node item: %w", err)
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
			if jobsSuccess {
				method = CheckJobs
			} else if clusterSuccess {
				method = CheckClusterStatus
			} else {
				method = "denied_response"
				confidence = "inferred"
			}
		}
		fpInput = &evidence.FingerprintInput{
			TargetID:           srvID.ID(),
			Product:            "Ray Dashboard",
			Vendor:             "Anyscale",
			SoftwareVersion:    normVersion,
			SoftwareVersionRaw: rawVersion,
			Commit:             commit,
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

func hasRayDenial(h http.Header, body []byte) bool {
	b := strings.ToLower(string(body))
	www := strings.ToLower(h.Get("Www-Authenticate"))
	return strings.Contains(b, "ray") || strings.Contains(www, "ray")
}

func hasRayJobsEvidence(jobs []jobEntry) bool {
	for _, j := range jobs {
		if j.SubmissionID != "" || j.Entrypoint != "" {
			return true
		}
	}
	return false
}

func extractClusterNodeCount(cs clusterStatusResponse) *int {
	if cs.Data.ClusterStatus != nil {
		if len(cs.Data.ClusterStatus.ActiveNodes) > 0 {
			total := 0
			for _, n := range cs.Data.ClusterStatus.ActiveNodes {
				total += n
			}
			return &total
		}
		if len(cs.Data.ClusterStatus.Nodes) > 0 {
			n := len(cs.Data.ClusterStatus.Nodes)
			return &n
		}
	}
	if cs.Data.LoadMetricsReport != nil && len(cs.Data.LoadMetricsReport.UsageByNode) > 0 {
		n := len(cs.Data.LoadMetricsReport.UsageByNode)
		return &n
	}
	return nil
}

func extractActorCount(a actorsResponse) *int {
	if a.Data.Result != nil && a.Data.Result.Total != nil {
		return a.Data.Result.Total
	}
	if a.Data.Actors != nil {
		n := len(a.Data.Actors)
		return &n
	}
	return nil
}

func rayTruncationReason(jobsTrunc, respTrunc bool, contentReasons []string) string {
	var parts []string
	if jobsTrunc {
		parts = append(parts, "job listing truncated at max_items bound")
	}
	if respTrunc {
		parts = append(parts, "response body truncated at max_response_bytes bound")
	}
	parts = append(parts, contentReasons...)
	return strings.Join(parts, "; ")
}
