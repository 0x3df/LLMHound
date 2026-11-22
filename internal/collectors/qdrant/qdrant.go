// Package qdrant provides anonymous, read-only enumeration of Qdrant vector
// database endpoints (version, collections, schema metadata, snapshot listing,
// and bounded point payload sampling) without fetching vectors or mutating state.
package qdrant

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
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
	// Surface is the canonical surface identifier for Qdrant.
	Surface = "qdrant"

	// DefaultPort is the default Qdrant HTTP REST port.
	DefaultPort = 6333

	// Allowlisted check identifiers.
	CheckVersion        = "qdrant_version"
	CheckCollections    = "qdrant_collections"
	CheckCollectionInfo = "qdrant_collection_info"
	CheckSnapshots      = "qdrant_snapshots"
	CheckPointsSample   = "qdrant_points_sample"
)

type rootResponse struct {
	Title   string `json:"title"`
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

type collectionEntry struct {
	Name string `json:"name"`
}

type collectionsResult struct {
	Collections []collectionEntry `json:"collections"`
}

type collectionsResponse struct {
	Result *collectionsResult `json:"result"`
	Status any                `json:"status"`
}

type vectorParams struct {
	Size     *int64 `json:"size,omitempty"`
	Distance string `json:"distance,omitempty"`
}

type collectionParams struct {
	Vectors json.RawMessage `json:"vectors,omitempty"`
}

type collectionConfig struct {
	Params collectionParams `json:"params,omitempty"`
}

type collectionInfoResult struct {
	Status              string           `json:"status,omitempty"`
	PointsCount         *int64           `json:"points_count,omitempty"`
	IndexedVectorsCount *int64           `json:"indexed_vectors_count,omitempty"`
	SegmentsCount       *int64           `json:"segments_count,omitempty"`
	Config              collectionConfig `json:"config,omitempty"`
}

type collectionInfoResponse struct {
	Result *collectionInfoResult `json:"result"`
}

type snapshotsResponse struct {
	Result []json.RawMessage `json:"result"`
}

type scrollRequest struct {
	Limit       int  `json:"limit"`
	WithPayload bool `json:"with_payload"`
	WithVector  bool `json:"with_vector"`
}

type scrollPoint struct {
	ID      json.RawMessage `json:"id"`
	Payload json.RawMessage `json:"payload"`
}

type scrollResult struct {
	Points         []scrollPoint   `json:"points"`
	NextPageOffset json.RawMessage `json:"next_page_offset"`
}

type scrollResponse struct {
	Result *scrollResult `json:"result"`
}

type parsedCollection struct {
	Name                string
	Status              string
	PointsCount         *int64
	IndexedVectorsCount *int64
	SegmentsCount       *int64
	Dimensions          *int64
	Distance            string
	VectorNames         []string
}

// Collector implements anonymous, read-only Qdrant enumeration.
type Collector struct {
	cfg         config.Config
	transport   *transport.Client
	contentSink content.Sink
}

// Option configures a Qdrant Collector.
type Option func(*Collector)

// WithTransport overrides the transport client (primarily for testing).
func WithTransport(tc *transport.Client) Option {
	return func(c *Collector) {
		c.transport = tc
	}
}

// WithContentSink configures where bounded content-tier point payload samples are written.
func WithContentSink(sink content.Sink) Option {
	return func(c *Collector) {
		c.contentSink = sink
	}
}

// New constructs a Qdrant collector with the given configuration.
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

// Collect performs allowlisted Qdrant metadata checks and optional bounded
// point payload sampling without retrieving vectors or mutating collections.
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

	srvID, err := graph.NewServiceIdentity(scope, graph.QdrantInstance, ep)
	if err != nil {
		return checkpoint.Result{}, fmt.Errorf("create service identity: %w", err)
	}

	evID := common.EvidenceID(scanID, srvID.ID(), obsTime)
	baseURL := strings.TrimSuffix(ep.String(), "/")
	sourceURL := baseURL + "/collections"

	var tlsInfo *transport.TLSInfo
	var redirects []transport.RedirectInfo
	var checks []common.CheckEntry
	var degraded []string

	var rawVersion string
	var normVersion string
	var commit string
	var verSuccess bool
	var verDenied bool
	var verErr error
	var serverQdrant bool

	var collectionNames []string
	var collectionsSuccess bool
	var collectionsDenied bool
	var collectionsErr error
	var collectionsTruncated bool
	var responseTruncated bool

	var snapshotsExposed bool
	var snapshotCount int

	// 1. Check: Root Version / Banner (GET /; never counts as anon_operations).
	{
		resp, reqErr := c.transport.Get(ctx, baseURL+"/")
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
				common.CheckEntry{CheckID: CheckCollections, Operation: CheckCollections, Outcome: graph.OutcomeSkipped, Reason: "prerequisite failed: TLS verification failed", OperationKind: graph.EnumerationOperation},
				common.CheckEntry{CheckID: CheckCollectionInfo, Operation: CheckCollectionInfo, Outcome: graph.OutcomeSkipped, Reason: "prerequisite failed: TLS verification failed", OperationKind: graph.EnumerationOperation},
				common.CheckEntry{CheckID: CheckSnapshots, Operation: CheckSnapshots, Outcome: graph.OutcomeSkipped, Reason: "prerequisite failed: TLS verification failed", OperationKind: graph.EnumerationOperation},
				common.CheckEntry{CheckID: CheckPointsSample, Operation: CheckPointsSample, Outcome: graph.OutcomeSkipped, Reason: "prerequisite failed: TLS verification failed", OperationKind: graph.ResourceReadOperation},
			)
			return c.buildFailedResult(target, scope, vantageKey, scanID, obsTime, evID, baseURL+"/", srvID, reason, checks, tlsInfo, redirects)
		}

		if reqErr != nil {
			verErr = reqErr
			reason := common.SanitizeError(reqErr)
			checks = append(checks, common.CheckEntry{
				CheckID: CheckVersion, Operation: CheckVersion, Outcome: graph.OutcomeFailed,
				Reason: reason, OperationKind: graph.EnumerationOperation,
				Details: map[string]any{"error": reason},
			})
		} else {
			if strings.Contains(strings.ToLower(resp.Header.Get("Server")), "qdrant") {
				serverQdrant = true
			}
			switch resp.StatusCode {
			case http.StatusOK:
				if resp.Truncated {
					responseTruncated = true
					checks = append(checks, common.CheckEntry{
						CheckID: CheckVersion, Operation: CheckVersion, Outcome: graph.OutcomeFailed,
						Reason: "root response truncated at max_response_bytes limit", OperationKind: graph.EnumerationOperation,
						Details: map[string]any{"http_status": resp.StatusCode, "truncated": true},
					})
				} else {
					var root rootResponse
					if err := json.Unmarshal(resp.Body, &root); err != nil {
						checks = append(checks, common.CheckEntry{
							CheckID: CheckVersion, Operation: CheckVersion, Outcome: graph.OutcomeFailed,
							Reason: "invalid JSON response from Qdrant root endpoint", OperationKind: graph.EnumerationOperation,
							Details: map[string]any{"http_status": resp.StatusCode},
						})
					} else if !strings.Contains(strings.ToLower(root.Title), "qdrant") && !serverQdrant {
						checks = append(checks, common.CheckEntry{
							CheckID: CheckVersion, Operation: CheckVersion, Outcome: graph.OutcomeFailed,
							Reason: "root JSON response does not identify Qdrant", OperationKind: graph.EnumerationOperation,
							Details: map[string]any{"http_status": resp.StatusCode},
						})
					} else {
						verSuccess = true
						rawVersion = common.BoundString(root.Version, 128)
						normVersion = common.NormalizeVersion(root.Version)
						commit = common.BoundString(root.Commit, 128)
						reason := "Qdrant root identified; runtime version not reported"
						if rawVersion != "" {
							reason = fmt.Sprintf("Qdrant version reported: %s", rawVersion)
						}
						checks = append(checks, common.CheckEntry{
							CheckID: CheckVersion, Operation: CheckVersion, Outcome: graph.OutcomeSuccess,
							Reason: reason, Anonymous: true,
							OperationKind: graph.EnumerationOperation, CountForAccess: false,
							Details: map[string]any{
								"http_status":          resp.StatusCode,
								"software_version":     normVersion,
								"software_version_raw": rawVersion,
								"commit":               commit,
							},
						})
					}
				}
			case http.StatusUnauthorized, http.StatusForbidden:
				verDenied = true
				checks = append(checks, common.CheckEntry{
					CheckID: CheckVersion, Operation: CheckVersion, Outcome: graph.OutcomeDenied,
					Reason:        fmt.Sprintf("HTTP %d: authentication or authorization required", resp.StatusCode),
					OperationKind: graph.EnumerationOperation,
					Details:       map[string]any{"http_status": resp.StatusCode},
				})
			case http.StatusNotFound:
				checks = append(checks, common.CheckEntry{
					CheckID: CheckVersion, Operation: CheckVersion, Outcome: graph.OutcomeFailed,
					Reason: "HTTP 404 not found (root version endpoint unavailable)", OperationKind: graph.EnumerationOperation,
					Details: map[string]any{"http_status": resp.StatusCode},
				})
			case http.StatusTooManyRequests:
				checks = append(checks, common.CheckEntry{
					CheckID: CheckVersion, Operation: CheckVersion, Outcome: graph.OutcomeFailed,
					Reason: "HTTP 429 rate limited", OperationKind: graph.EnumerationOperation,
					Details: map[string]any{"http_status": resp.StatusCode},
				})
			default:
				checks = append(checks, common.CheckEntry{
					CheckID: CheckVersion, Operation: CheckVersion, Outcome: graph.OutcomeFailed,
					Reason:        fmt.Sprintf("HTTP %d unexpected status", resp.StatusCode),
					OperationKind: graph.EnumerationOperation,
					Details:       map[string]any{"http_status": resp.StatusCode},
				})
			}
		}
	}

	// 2. Check: Collections Inventory (GET /collections).
	{
		resp, reqErr := c.transport.Get(ctx, baseURL+"/collections")
		common.AbsorbTransport(resp, &tlsInfo, &redirects)

		if common.IsTLSFailure(tlsInfo, c.cfg.Insecure) {
			reason := common.SanitizeError(reqErr)
			if reason == "" {
				reason = "TLS certificate verification failed: " + common.BoundString(tlsInfo.VerificationReason, 200)
			}
			checks = append(checks,
				common.CheckEntry{
					CheckID: CheckCollections, Operation: CheckCollections, Outcome: graph.OutcomeFailed,
					Reason: reason, OperationKind: graph.EnumerationOperation,
					Details: map[string]any{"tls_error": common.BoundString(tlsInfo.VerificationReason, 200)},
				},
				common.CheckEntry{CheckID: CheckCollectionInfo, Operation: CheckCollectionInfo, Outcome: graph.OutcomeSkipped, Reason: "prerequisite failed: TLS verification failed", OperationKind: graph.EnumerationOperation},
				common.CheckEntry{CheckID: CheckSnapshots, Operation: CheckSnapshots, Outcome: graph.OutcomeSkipped, Reason: "prerequisite failed: TLS verification failed", OperationKind: graph.EnumerationOperation},
				common.CheckEntry{CheckID: CheckPointsSample, Operation: CheckPointsSample, Outcome: graph.OutcomeSkipped, Reason: "prerequisite failed: TLS verification failed", OperationKind: graph.ResourceReadOperation},
			)
			return c.buildFailedResult(target, scope, vantageKey, scanID, obsTime, evID, sourceURL, srvID, reason, checks, tlsInfo, redirects)
		}

		if reqErr != nil {
			collectionsErr = reqErr
			reason := common.SanitizeError(reqErr)
			checks = append(checks, common.CheckEntry{
				CheckID: CheckCollections, Operation: CheckCollections, Outcome: graph.OutcomeFailed,
				Reason: reason, OperationKind: graph.EnumerationOperation,
				Details: map[string]any{"error": reason},
			})
		} else {
			if strings.Contains(strings.ToLower(resp.Header.Get("Server")), "qdrant") {
				serverQdrant = true
			}
			switch resp.StatusCode {
			case http.StatusOK:
				var cResp collectionsResponse
				if resp.Truncated {
					responseTruncated = true
					checks = append(checks, common.CheckEntry{
						CheckID: CheckCollections, Operation: CheckCollections, Outcome: graph.OutcomeFailed,
						Reason: "collections response truncated at max_response_bytes limit", OperationKind: graph.EnumerationOperation,
						Details: map[string]any{"http_status": resp.StatusCode, "truncated": true},
					})
				} else if err := json.Unmarshal(resp.Body, &cResp); err != nil || cResp.Result == nil || cResp.Result.Collections == nil {
					checks = append(checks, common.CheckEntry{
						CheckID: CheckCollections, Operation: CheckCollections, Outcome: graph.OutcomeFailed,
						Reason: "invalid JSON response from /collections", OperationKind: graph.EnumerationOperation,
						Details: map[string]any{"http_status": resp.StatusCode},
					})
				} else {
					seen := make(map[string]bool, len(cResp.Result.Collections))
					var allNames []string
					for _, col := range cResp.Result.Collections {
						name := strings.TrimSpace(col.Name)
						if name == "" || seen[name] {
							continue
						}
						seen[name] = true
						allNames = append(allNames, name)
					}
					maxItems := c.cfg.Bounds.MaxItems
					if maxItems <= 0 {
						maxItems = 10000
					}
					if len(allNames) > maxItems {
						collectionsTruncated = true
						collectionNames = allNames[:maxItems]
					} else {
						collectionNames = allNames
					}
					collectionsSuccess = true
					checks = append(checks, common.CheckEntry{
						CheckID: CheckCollections, Operation: CheckCollections, Outcome: graph.OutcomeSuccess,
						Reason: "collections enumerated anonymously", Anonymous: true,
						OperationKind: graph.EnumerationOperation, CountForAccess: true,
						Details: map[string]any{
							"http_status":      resp.StatusCode,
							"collection_count": len(collectionNames),
							"truncated":        collectionsTruncated,
						},
					})
				}
			case http.StatusUnauthorized, http.StatusForbidden:
				collectionsDenied = true
				checks = append(checks, common.CheckEntry{
					CheckID: CheckCollections, Operation: CheckCollections, Outcome: graph.OutcomeDenied,
					Reason:        fmt.Sprintf("HTTP %d: authentication or authorization required", resp.StatusCode),
					OperationKind: graph.EnumerationOperation,
					Details:       map[string]any{"http_status": resp.StatusCode},
				})
			case http.StatusNotFound:
				checks = append(checks, common.CheckEntry{
					CheckID: CheckCollections, Operation: CheckCollections, Outcome: graph.OutcomeFailed,
					Reason: "HTTP 404 not found (/collections endpoint unavailable)", OperationKind: graph.EnumerationOperation,
					Details: map[string]any{"http_status": resp.StatusCode},
				})
			case http.StatusTooManyRequests:
				checks = append(checks, common.CheckEntry{
					CheckID: CheckCollections, Operation: CheckCollections, Outcome: graph.OutcomeFailed,
					Reason: "HTTP 429 rate limited", OperationKind: graph.EnumerationOperation,
					Details: map[string]any{"http_status": resp.StatusCode},
				})
			default:
				checks = append(checks, common.CheckEntry{
					CheckID: CheckCollections, Operation: CheckCollections, Outcome: graph.OutcomeFailed,
					Reason:        fmt.Sprintf("HTTP %d unexpected status", resp.StatusCode),
					OperationKind: graph.EnumerationOperation,
					Details:       map[string]any{"http_status": resp.StatusCode},
				})
			}
		}
	}

	// 3. Check: Per-Collection Schema Info (GET /collections/<name>).
	parsedCols := make(map[string]parsedCollection, len(collectionNames))
	if !collectionsSuccess {
		checks = append(checks, common.CheckEntry{
			CheckID: CheckCollectionInfo, Operation: CheckCollectionInfo, Outcome: graph.OutcomeSkipped,
			Reason: "prerequisite failed: collections listing unavailable", OperationKind: graph.EnumerationOperation,
		})
	} else if len(collectionNames) == 0 {
		checks = append(checks, common.CheckEntry{
			CheckID: CheckCollectionInfo, Operation: CheckCollectionInfo, Outcome: graph.OutcomeSkipped,
			Reason: "no collections available to inspect", OperationKind: graph.EnumerationOperation,
		})
	} else {
		infoSuccess := 0
		infoDenied := 0
		var infoErrors []string
		for _, name := range collectionNames {
			if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\") {
				infoErrors = append(infoErrors, fmt.Sprintf("%q: invalid collection segment", name))
				continue
			}
			infoURL := baseURL + "/collections/" + url.PathEscape(name)
			resp, reqErr := c.transport.Get(ctx, infoURL)
			common.AbsorbTransport(resp, &tlsInfo, &redirects)
			if reqErr != nil {
				infoErrors = append(infoErrors, fmt.Sprintf("%s: %s", name, common.SanitizeError(reqErr)))
				continue
			}
			switch resp.StatusCode {
			case http.StatusOK:
				if resp.Truncated {
					responseTruncated = true
					infoErrors = append(infoErrors, fmt.Sprintf("%s: response truncated at max_response_bytes", name))
					continue
				}
				var ir collectionInfoResponse
				if err := json.Unmarshal(resp.Body, &ir); err != nil || ir.Result == nil {
					infoErrors = append(infoErrors, fmt.Sprintf("%s: invalid JSON", name))
					continue
				}
				dims, dist, vecNames := parseVectorsConfig(ir.Result.Config.Params.Vectors)
				parsedCols[name] = parsedCollection{
					Name:                name,
					Status:              common.BoundString(ir.Result.Status, 64),
					PointsCount:         ir.Result.PointsCount,
					IndexedVectorsCount: ir.Result.IndexedVectorsCount,
					SegmentsCount:       ir.Result.SegmentsCount,
					Dimensions:          dims,
					Distance:            dist,
					VectorNames:         vecNames,
				}
				infoSuccess++
			case http.StatusUnauthorized, http.StatusForbidden:
				infoDenied++
				infoErrors = append(infoErrors, fmt.Sprintf("%s: HTTP %d", name, resp.StatusCode))
			default:
				infoErrors = append(infoErrors, fmt.Sprintf("%s: HTTP %d", name, resp.StatusCode))
			}
		}

		switch {
		case infoSuccess > 0:
			details := map[string]any{
				"inspected_count": infoSuccess,
				"total_count":     len(collectionNames),
			}
			if len(infoErrors) > 0 {
				details["errors"] = infoErrors
				degraded = append(degraded, fmt.Sprintf("collection info retrieved for %d of %d collections", infoSuccess, len(collectionNames)))
			}
			checks = append(checks, common.CheckEntry{
				CheckID: CheckCollectionInfo, Operation: CheckCollectionInfo, Outcome: graph.OutcomeSuccess,
				Reason:    fmt.Sprintf("collection schema metadata retrieved for %d of %d collections", infoSuccess, len(collectionNames)),
				Anonymous: true, OperationKind: graph.EnumerationOperation, CountForAccess: true, Details: details,
			})
		case infoDenied > 0 && infoDenied == len(collectionNames):
			degraded = append(degraded, "collection info denied for all collections")
			checks = append(checks, common.CheckEntry{
				CheckID: CheckCollectionInfo, Operation: CheckCollectionInfo, Outcome: graph.OutcomeDenied,
				Reason: "authentication or authorization required for collection info", OperationKind: graph.EnumerationOperation,
				Details: map[string]any{"errors": infoErrors},
			})
		default:
			degraded = append(degraded, "collection info retrieval failed")
			checks = append(checks, common.CheckEntry{
				CheckID: CheckCollectionInfo, Operation: CheckCollectionInfo, Outcome: graph.OutcomeFailed,
				Reason: "failed to retrieve collection info: " + strings.Join(infoErrors, "; "), OperationKind: graph.EnumerationOperation,
				Details: map[string]any{"errors": infoErrors},
			})
		}
	}

	// 4. Check: Snapshots Listing (strictly GET /snapshots).
	{
		resp, reqErr := c.transport.Get(ctx, baseURL+"/snapshots")
		common.AbsorbTransport(resp, &tlsInfo, &redirects)
		if reqErr != nil {
			reason := common.SanitizeError(reqErr)
			degraded = append(degraded, "snapshots check failed: "+reason)
			checks = append(checks, common.CheckEntry{
				CheckID: CheckSnapshots, Operation: CheckSnapshots, Outcome: graph.OutcomeFailed,
				Reason: reason, OperationKind: graph.EnumerationOperation,
				Details: map[string]any{"error": reason},
			})
		} else {
			switch resp.StatusCode {
			case http.StatusOK:
				var sResp snapshotsResponse
				if resp.Truncated {
					responseTruncated = true
					degraded = append(degraded, "snapshots response truncated at max_response_bytes")
					checks = append(checks, common.CheckEntry{
						CheckID: CheckSnapshots, Operation: CheckSnapshots, Outcome: graph.OutcomeFailed,
						Reason: "snapshots response truncated at max_response_bytes limit", OperationKind: graph.EnumerationOperation,
						Details: map[string]any{"http_status": resp.StatusCode, "truncated": true},
					})
				} else if err := json.Unmarshal(resp.Body, &sResp); err != nil || sResp.Result == nil {
					degraded = append(degraded, "invalid JSON response from /snapshots")
					checks = append(checks, common.CheckEntry{
						CheckID: CheckSnapshots, Operation: CheckSnapshots, Outcome: graph.OutcomeFailed,
						Reason: "invalid JSON response from /snapshots", OperationKind: graph.EnumerationOperation,
						Details: map[string]any{"http_status": resp.StatusCode},
					})
				} else {
					snapshotsExposed = true
					snapshotCount = len(sResp.Result)
					checks = append(checks, common.CheckEntry{
						CheckID: CheckSnapshots, Operation: CheckSnapshots, Outcome: graph.OutcomeSuccess,
						Reason: "snapshots listed anonymously", Anonymous: true,
						OperationKind: graph.EnumerationOperation, CountForAccess: true,
						Details: map[string]any{"http_status": resp.StatusCode, "snapshot_count": snapshotCount},
					})
				}
			case http.StatusUnauthorized, http.StatusForbidden:
				degraded = append(degraded, fmt.Sprintf("snapshots endpoint denied (HTTP %d)", resp.StatusCode))
				checks = append(checks, common.CheckEntry{
					CheckID: CheckSnapshots, Operation: CheckSnapshots, Outcome: graph.OutcomeDenied,
					Reason:        fmt.Sprintf("HTTP %d: authentication or authorization required", resp.StatusCode),
					OperationKind: graph.EnumerationOperation,
					Details:       map[string]any{"http_status": resp.StatusCode},
				})
			case http.StatusNotFound:
				degraded = append(degraded, "snapshots endpoint unavailable (HTTP 404)")
				checks = append(checks, common.CheckEntry{
					CheckID: CheckSnapshots, Operation: CheckSnapshots, Outcome: graph.OutcomeFailed,
					Reason: "HTTP 404 not found (snapshots endpoint unavailable)", OperationKind: graph.EnumerationOperation,
					Details: map[string]any{"http_status": resp.StatusCode},
				})
			case http.StatusTooManyRequests:
				degraded = append(degraded, "snapshots endpoint rate limited (HTTP 429)")
				checks = append(checks, common.CheckEntry{
					CheckID: CheckSnapshots, Operation: CheckSnapshots, Outcome: graph.OutcomeFailed,
					Reason: "HTTP 429 rate limited", OperationKind: graph.EnumerationOperation,
					Details: map[string]any{"http_status": resp.StatusCode},
				})
			default:
				degraded = append(degraded, fmt.Sprintf("snapshots endpoint returned HTTP %d", resp.StatusCode))
				checks = append(checks, common.CheckEntry{
					CheckID: CheckSnapshots, Operation: CheckSnapshots, Outcome: graph.OutcomeFailed,
					Reason:        fmt.Sprintf("HTTP %d unexpected status", resp.StatusCode),
					OperationKind: graph.EnumerationOperation,
					Details:       map[string]any{"http_status": resp.StatusCode},
				})
			}
		}
	}

	// 5. Check: Bounded Point Payload Sampling (POST /collections/<name>/points/scroll, content tier).
	var contentSummary *graph.ContentSummary
	var contentTruncated bool
	var contentTruncReasons []string
	if !c.cfg.Content.EnabledFor(Surface) {
		checks = append(checks, common.CheckEntry{
			CheckID: CheckPointsSample, Operation: CheckPointsSample, Outcome: graph.OutcomeSkipped,
			Reason: "content collection disabled by policy", OperationKind: graph.ResourceReadOperation,
			Details: map[string]any{"skipped": true, "policy": "content_disabled"},
		})
	} else if !collectionsSuccess {
		checks = append(checks, common.CheckEntry{
			CheckID: CheckPointsSample, Operation: CheckPointsSample, Outcome: graph.OutcomeSkipped,
			Reason: "prerequisite failed: collections listing unavailable", OperationKind: graph.ResourceReadOperation,
		})
	} else if len(collectionNames) == 0 {
		checks = append(checks, common.CheckEntry{
			CheckID: CheckPointsSample, Operation: CheckPointsSample, Outcome: graph.OutcomeSkipped,
			Reason: "no collections available to sample", OperationKind: graph.ResourceReadOperation,
		})
	} else {
		sampleLimit := c.cfg.Content.MaxSamplePoints
		if sampleLimit <= 0 {
			sampleLimit = config.DefaultContentMaxSamplePoints
		}
		reqBody, _ := json.Marshal(scrollRequest{Limit: sampleLimit, WithPayload: true, WithVector: false})
		budget := content.NewBudget(c.cfg.Content, secrets.NewRedactor(c.cfg.Secrets))

		scrollSuccess := 0
		scrollDenied := 0
		var scrollErrors []string

		for _, name := range collectionNames {
			if budget.ServiceLimitReached() {
				budget.MarkTruncated(fmt.Sprintf("content service byte limit (%d) reached", c.cfg.Content.MaxServiceBytes))
				break
			}
			if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\") {
				scrollErrors = append(scrollErrors, fmt.Sprintf("%q: invalid collection segment", name))
				continue
			}
			scrollURL := baseURL + "/collections/" + url.PathEscape(name) + "/points/scroll"
			resp, reqErr := c.transport.Post(ctx, scrollURL, "application/json", reqBody)
			common.AbsorbTransport(resp, &tlsInfo, &redirects)
			if reqErr != nil {
				scrollErrors = append(scrollErrors, fmt.Sprintf("%s: %s", name, common.SanitizeError(reqErr)))
				continue
			}
			if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
				scrollDenied++
				scrollErrors = append(scrollErrors, fmt.Sprintf("%s: HTTP %d", name, resp.StatusCode))
				continue
			}
			if resp.StatusCode != http.StatusOK {
				scrollErrors = append(scrollErrors, fmt.Sprintf("%s: HTTP %d", name, resp.StatusCode))
				continue
			}
			if resp.Truncated {
				responseTruncated = true
				budget.MarkTruncated(fmt.Sprintf("scroll response for %s truncated at max_response_bytes", name))
				scrollErrors = append(scrollErrors, fmt.Sprintf("%s: response truncated at max_response_bytes limit", name))
				continue
			}
			var sr scrollResponse
			if err := json.Unmarshal(resp.Body, &sr); err != nil || sr.Result == nil {
				scrollErrors = append(scrollErrors, fmt.Sprintf("%s: invalid JSON", name))
				continue
			}
			scrollSuccess++

			pts := sr.Result.Points
			nextOffset := strings.TrimSpace(string(sr.Result.NextPageOffset))
			if (nextOffset != "" && nextOffset != "null") || len(pts) > sampleLimit {
				budget.MarkTruncated(fmt.Sprintf("collection %s truncated at max_sample_points (%d)", name, sampleLimit))
			}
			if len(pts) > sampleLimit {
				pts = pts[:sampleLimit]
			}

			var collIDStr string
			if cid, err := graph.NewResourceIdentity(scope, graph.VectorCollection, srvID, name); err == nil {
				collIDStr = cid.ID()
			}

			for idx, pt := range pts {
				trimmed := bytes.TrimSpace(pt.Payload)
				if len(trimmed) == 0 || string(trimmed) == "null" || string(trimmed) == "{}" {
					continue
				}
				if content.LooksBinary(trimmed) {
					continue
				}
				if ok, _ := budget.ClaimResourceItem(name); !ok {
					break
				}
				pointID := formatPointID(pt.ID, idx)
				rec, added, addErr := budget.Add(content.RecordInput{
					DeploymentScope: scope,
					ScanID:          scanID,
					VantageKey:      vantageKey,
					ServiceID:       srvID.ID(),
					ResourceID:      collIDStr,
					Surface:         Surface,
					CheckID:         CheckPointsSample,
					Source:          scrollURL,
					Kind:            content.KindSample,
					Location:        fmt.Sprintf("%s#%s", name, pointID),
					MediaType:       "application/json",
					ObservedAt:      obsTime,
					Body:            string(trimmed),
				})
				if addErr != nil {
					return checkpoint.Result{}, fmt.Errorf("create qdrant sample record: %w", addErr)
				}
				if added && c.contentSink != nil {
					if err := c.contentSink.Write(rec); err != nil {
						return checkpoint.Result{}, fmt.Errorf("write qdrant sample record: %w", err)
					}
				}
			}
		}

		contentTruncated = budget.Truncated()
		contentTruncReasons = budget.Reasons()
		contentSummary = common.ContentSummaryFromBudget(budget, obsTime, nil, nil)

		switch {
		case scrollSuccess > 0:
			details := map[string]any{
				"collections_sampled": scrollSuccess,
				"content_items":       len(budget.Records()),
				"content_bytes":       budget.Bytes(),
				"content_truncated":   contentTruncated,
			}
			if len(scrollErrors) > 0 {
				details["errors"] = scrollErrors
				degraded = append(degraded, fmt.Sprintf("point payload sampling succeeded for %d of %d collections", scrollSuccess, len(collectionNames)))
			}
			if found := budget.Findings(); len(found) > 0 {
				details["detected_exposures"] = content.ExposureDetails(found)
			}
			checks = append(checks, common.CheckEntry{
				CheckID: CheckPointsSample, Operation: CheckPointsSample, Outcome: graph.OutcomeSuccess,
				Reason:        fmt.Sprintf("point payload samples collected for %d of %d collections", scrollSuccess, len(collectionNames)),
				OperationKind: graph.ResourceReadOperation, CountForAccess: false, Details: details,
			})
		case scrollDenied > 0 && scrollDenied == len(collectionNames):
			degraded = append(degraded, "point payload sampling denied for all collections")
			checks = append(checks, common.CheckEntry{
				CheckID: CheckPointsSample, Operation: CheckPointsSample, Outcome: graph.OutcomeDenied,
				Reason: "authentication or authorization required for point sampling", OperationKind: graph.ResourceReadOperation,
				Details: map[string]any{"errors": scrollErrors},
			})
		default:
			degraded = append(degraded, "point payload sampling failed")
			checks = append(checks, common.CheckEntry{
				CheckID: CheckPointsSample, Operation: CheckPointsSample, Outcome: graph.OutcomeFailed,
				Reason: "failed to sample point payloads: " + strings.Join(scrollErrors, "; "), OperationKind: graph.ResourceReadOperation,
				Details: map[string]any{"errors": scrollErrors},
			})
		}
	}

	// 6. Determine coverage and status.
	var finalCoverage graph.Coverage
	var finalCoverageReason string
	var finalStatus checkpoint.TargetStatus

	switch {
	case verErr != nil && collectionsErr != nil:
		finalCoverage = graph.CoverageFailed
		finalStatus = checkpoint.TargetStatusFailed
		finalCoverageReason = "target unreachable: " + common.SanitizeError(verErr)
	case verSuccess && collectionsSuccess:
		if collectionsTruncated || responseTruncated || contentTruncated {
			finalCoverage = graph.CoverageTruncated
			finalStatus = checkpoint.TargetStatusPartial
			finalCoverageReason = qdrantTruncationReason(collectionsTruncated, responseTruncated, contentTruncReasons)
		} else if len(degraded) > 0 {
			finalCoverage = graph.CoveragePartial
			finalStatus = checkpoint.TargetStatusPartial
			finalCoverageReason = strings.Join(degraded, "; ")
		} else {
			finalCoverage = graph.CoverageComplete
			finalStatus = checkpoint.TargetStatusCompleted
		}
	case collectionsSuccess && !verSuccess:
		if collectionsTruncated || responseTruncated || contentTruncated {
			finalCoverage = graph.CoverageTruncated
			finalStatus = checkpoint.TargetStatusPartial
			finalCoverageReason = qdrantTruncationReason(collectionsTruncated, responseTruncated, contentTruncReasons)
		} else {
			finalCoverage = graph.CoveragePartial
			finalStatus = checkpoint.TargetStatusPartial
			finalCoverageReason = "collections enumerated, but root version endpoint unavailable or denied"
		}
	case verSuccess && !collectionsSuccess:
		if responseTruncated {
			finalCoverage = graph.CoverageTruncated
			finalStatus = checkpoint.TargetStatusPartial
			finalCoverageReason = "response body truncated at max_response_bytes bound"
		} else {
			finalCoverage = graph.CoveragePartial
			finalStatus = checkpoint.TargetStatusPartial
			finalCoverageReason = "Qdrant root identified, but collections listing unavailable or denied"
		}
	case verDenied && collectionsDenied:
		finalCoverage = graph.CoveragePartial
		finalStatus = checkpoint.TargetStatusPartial
		finalCoverageReason = "authentication required: all metadata endpoints denied access"
	case (verDenied || collectionsDenied) && serverQdrant:
		finalCoverage = graph.CoveragePartial
		finalStatus = checkpoint.TargetStatusPartial
		finalCoverageReason = "authentication required on Qdrant endpoint"
	default:
		finalCoverage = graph.CoverageFailed
		finalStatus = checkpoint.TargetStatusFailed
		finalCoverageReason = "enumeration failed: target not confirmed as Qdrant"
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
			Name:       fmt.Sprintf("Qdrant · %s:%d", ep.Host(), ep.Port()),
			Product:    "Qdrant",
			Vendor:     "Qdrant",
			Commit:     commit,
			VantageKey: vantageKey,
			Access:     access,
			TLS:        common.TLSSummary(tlsInfo),
			Content:    contentSummary,
		}
		if collectionsSuccess {
			facts.CollectionCount = common.IntPtr(len(collectionNames))
		}
		srvProps := facts.Properties()
		if normVersion != "" {
			srvProps["software_version"] = normVersion
		}
		if rawVersion != "" {
			srvProps["software_version_raw"] = rawVersion
		}
		if snapshotsExposed {
			srvProps["snapshots_exposed"] = true
			srvProps["snapshot_count"] = snapshotCount
		}

		srvNode, err := graph.NewNode(srvID, obs)
		if err != nil {
			return checkpoint.Result{}, fmt.Errorf("create QdrantInstance node: %w", err)
		}
		srvItem, err := emitter.NewNodeItem(srvNode, srvProps)
		if err != nil {
			return checkpoint.Result{}, fmt.Errorf("create QdrantInstance node item: %w", err)
		}
		nodes = append(nodes, srvItem)

		for _, name := range collectionNames {
			collID, err := graph.NewResourceIdentity(scope, graph.VectorCollection, srvID, name)
			if err != nil {
				continue
			}
			collNode, err := graph.NewNode(collID, obs)
			if err != nil {
				continue
			}
			collProps := map[string]any{
				"name":            name,
				"collection_name": name,
			}
			if info, ok := parsedCols[name]; ok {
				if info.Status != "" {
					collProps["status"] = info.Status
				}
				if info.PointsCount != nil {
					collProps["points_count"] = *info.PointsCount
				}
				if info.IndexedVectorsCount != nil {
					collProps["indexed_vectors_count"] = *info.IndexedVectorsCount
				}
				if info.SegmentsCount != nil {
					collProps["segments_count"] = *info.SegmentsCount
				}
				if info.Dimensions != nil {
					collProps["dimensions"] = *info.Dimensions
				}
				if info.Distance != "" {
					collProps["distance"] = info.Distance
				}
				if len(info.VectorNames) > 0 {
					collProps["vector_names"] = info.VectorNames
				}
			}

			collItem, err := emitter.NewNodeItem(collNode, collProps)
			if err != nil {
				continue
			}
			containsEdge, err := graph.NewTopologyEdge(graph.Contains, srvID.Reference(), collID.Reference(), obs)
			if err != nil {
				continue
			}
			nodes = append(nodes, collItem)
			edges = append(edges, containsEdge)
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

		method := CheckCollections
		confidence := "inferred"
		if verSuccess {
			method = CheckVersion
			confidence = "exact"
		} else if serverQdrant {
			confidence = "exact"
		}
		fpInput = &evidence.FingerprintInput{
			TargetID:           srvID.ID(),
			Product:            "Qdrant",
			Vendor:             "Qdrant",
			SoftwareVersion:    normVersion,
			SoftwareVersionRaw: rawVersion,
			Commit:             commit,
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

func parseVectorsConfig(raw json.RawMessage) (dims *int64, distance string, vectorNames []string) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return nil, "", nil
	}
	var single vectorParams
	if json.Unmarshal(trimmed, &single) == nil && (single.Size != nil || single.Distance != "") {
		return single.Size, common.BoundString(single.Distance, 64), nil
	}
	var named map[string]vectorParams
	if json.Unmarshal(trimmed, &named) == nil && len(named) > 0 {
		vectorNames = make([]string, 0, len(named))
		var commonSize *int64
		var commonDist string
		sameSize := true
		sameDist := true
		first := true
		for name, vp := range named {
			cleanName := common.BoundString(name, 128)
			if cleanName == "" {
				continue
			}
			vectorNames = append(vectorNames, cleanName)
			if first {
				commonSize = vp.Size
				commonDist = common.BoundString(vp.Distance, 64)
				first = false
			} else {
				if (commonSize == nil) != (vp.Size == nil) || (commonSize != nil && vp.Size != nil && *commonSize != *vp.Size) {
					sameSize = false
				}
				if commonDist != common.BoundString(vp.Distance, 64) {
					sameDist = false
				}
			}
		}
		sort.Strings(vectorNames)
		if sameSize {
			dims = commonSize
		}
		if sameDist {
			distance = commonDist
		}
		return dims, distance, vectorNames
	}
	return nil, "", nil
}

func formatPointID(raw json.RawMessage, fallbackIdx int) string {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return strconv.Itoa(fallbackIdx)
	}
	var s string
	if json.Unmarshal(trimmed, &s) == nil && strings.TrimSpace(s) != "" {
		return common.BoundString(s, 128)
	}
	return common.BoundString(string(trimmed), 128)
}

func qdrantTruncationReason(collectionsTruncated, responseTruncated bool, contentReasons []string) string {
	var parts []string
	if collectionsTruncated {
		parts = append(parts, "collections listing truncated at max_items bound")
	}
	if responseTruncated {
		parts = append(parts, "response body truncated at max_response_bytes bound")
	}
	parts = append(parts, contentReasons...)
	if len(parts) == 0 {
		parts = append(parts, "qdrant collection truncated at configured bounds")
	}
	return strings.Join(parts, "; ")
}
