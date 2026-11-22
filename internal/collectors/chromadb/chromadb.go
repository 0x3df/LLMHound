// Package chromadb provides anonymous, read-only metadata enumeration of
// ChromaDB vector stores (heartbeat, version, auth identity, collections,
// counts, and bounded document/metadata samples) without fetching embeddings.
package chromadb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
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
	// Surface is the canonical surface identifier for ChromaDB.
	Surface = "chromadb"

	// DefaultPort is the default listener port for ChromaDB.
	DefaultPort = 8000

	// Allowlisted check identifiers.
	CheckVersion         = "chromadb_version"
	CheckAuthIdentity    = "chromadb_auth_identity"
	CheckCollections     = "chromadb_collections"
	CheckCollectionCount = "chromadb_collection_count"
	CheckDocumentsSample = "chromadb_documents_sample"
)

type authIdentityResponse struct {
	UserID    string   `json:"user_id,omitempty"`
	Tenant    string   `json:"tenant,omitempty"`
	Databases []string `json:"databases,omitempty"`
}

type collectionEntry struct {
	ID       string         `json:"id"`
	Name     string         `json:"name"`
	Tenant   string         `json:"tenant,omitempty"`
	Database string         `json:"database,omitempty"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

type getDocsRequest struct {
	Limit   int      `json:"limit"`
	Include []string `json:"include"`
}

// getDocsResponse deliberately omits "embeddings" so embedding vectors are
// never decoded or retained.
type getDocsResponse struct {
	IDs       []string         `json:"ids"`
	Documents []any            `json:"documents"`
	Metadatas []map[string]any `json:"metadatas"`
}

// Collector implements anonymous, read-only ChromaDB enumeration.
type Collector struct {
	cfg         config.Config
	transport   *transport.Client
	contentSink content.Sink
}

// Option configures a ChromaDB Collector.
type Option func(*Collector)

// WithTransport overrides the transport client (primarily for testing).
func WithTransport(tc *transport.Client) Option {
	return func(c *Collector) {
		c.transport = tc
	}
}

// WithContentSink configures where bounded document/metadata samples are written.
func WithContentSink(sink content.Sink) Option {
	return func(c *Collector) {
		c.contentSink = sink
	}
}

// New constructs a ChromaDB collector with the given configuration.
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

// Collect performs allowlisted GET metadata checks and bounded document/metadata
// sampling on a ChromaDB server without ever fetching embeddings.
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

	srvID, err := graph.NewServiceIdentity(scope, graph.ChromaInstance, ep)
	if err != nil {
		return checkpoint.Result{}, fmt.Errorf("create service identity: %w", err)
	}

	evID := common.EvidenceID(scanID, srvID.ID(), obsTime)
	baseURL := strings.TrimSuffix(ep.String(), "/")

	var tlsInfo *transport.TLSInfo
	var redirects []transport.RedirectInfo
	var checks []common.CheckEntry
	var degraded []string

	var chromaConfirmed bool
	var deniedConfirmed bool
	var apiVersion string
	var rawVersion, normVersion string
	var verSuccess, verDenied bool
	var verErr error
	var responseTruncated bool

	maxItems := c.cfg.Bounds.MaxItems
	if maxItems <= 0 {
		maxItems = 10000
	}

	// 1. Check: Heartbeat + Version (v2 first, falling back to v1).
	{
		hbResp, hbErr := c.transport.Get(ctx, baseURL+"/api/v2/heartbeat")
		common.AbsorbTransport(hbResp, &tlsInfo, &redirects)

		if common.IsTLSFailure(tlsInfo, c.cfg.Insecure) {
			reason := common.SanitizeError(hbErr)
			if reason == "" {
				reason = "TLS certificate verification failed: " + common.BoundString(tlsInfo.VerificationReason, 200)
			}
			checks = append(checks,
				common.CheckEntry{
					CheckID: CheckVersion, Operation: CheckVersion, Outcome: graph.OutcomeFailed,
					Reason: reason, OperationKind: graph.EnumerationOperation,
					Details: map[string]any{"tls_error": common.BoundString(tlsInfo.VerificationReason, 200)},
				},
				common.CheckEntry{CheckID: CheckAuthIdentity, Operation: CheckAuthIdentity, Outcome: graph.OutcomeSkipped, Reason: "prerequisite failed: TLS verification failed", OperationKind: graph.EnumerationOperation},
				common.CheckEntry{CheckID: CheckCollections, Operation: CheckCollections, Outcome: graph.OutcomeSkipped, Reason: "prerequisite failed: TLS verification failed", OperationKind: graph.EnumerationOperation},
				common.CheckEntry{CheckID: CheckCollectionCount, Operation: CheckCollectionCount, Outcome: graph.OutcomeSkipped, Reason: "prerequisite failed: TLS verification failed", OperationKind: graph.EnumerationOperation},
				common.CheckEntry{CheckID: CheckDocumentsSample, Operation: CheckDocumentsSample, Outcome: graph.OutcomeSkipped, Reason: "prerequisite failed: TLS verification failed", OperationKind: graph.ResourceReadOperation},
			)
			return c.buildFailedResult(target, scope, vantageKey, scanID, obsTime, evID, baseURL+"/api/v2/heartbeat", srvID, reason, checks, tlsInfo, redirects)
		}

		if hbErr == nil && hbResp.StatusCode == http.StatusOK && isChromaHeartbeat(hbResp.Body) {
			chromaConfirmed = true
			apiVersion = "v2"
		} else if hbErr == nil && (hbResp.StatusCode == http.StatusUnauthorized || hbResp.StatusCode == http.StatusForbidden) {
			if hasChromaDenial(hbResp.Header, hbResp.Body) {
				chromaConfirmed = true
				deniedConfirmed = true
			}
			verDenied = true
		} else if hbErr == nil && (hbResp.StatusCode == http.StatusNotFound || hbResp.StatusCode == http.StatusGone) {
			hbV1Resp, hbV1Err := c.transport.Get(ctx, baseURL+"/api/v1/heartbeat")
			common.AbsorbTransport(hbV1Resp, &tlsInfo, &redirects)
			if hbV1Err == nil && hbV1Resp.StatusCode == http.StatusOK && isChromaHeartbeat(hbV1Resp.Body) {
				chromaConfirmed = true
				apiVersion = "v1"
			} else if hbV1Err == nil && (hbV1Resp.StatusCode == http.StatusUnauthorized || hbV1Resp.StatusCode == http.StatusForbidden) {
				if hasChromaDenial(hbV1Resp.Header, hbV1Resp.Body) {
					chromaConfirmed = true
					deniedConfirmed = true
				}
				verDenied = true
			}
		} else if hbErr != nil {
			verErr = hbErr
		}

		if apiVersion == "" && chromaConfirmed {
			apiVersion = "v2"
		}

		// Fetch /api/<v>/version when possible.
		verPath := "/api/v2/version"
		if apiVersion == "v1" {
			verPath = "/api/v1/version"
		}
		vResp, vErr := c.transport.Get(ctx, baseURL+verPath)
		common.AbsorbTransport(vResp, &tlsInfo, &redirects)
		if vErr == nil && vResp != nil {
			if vResp.StatusCode == http.StatusNotFound && apiVersion != "v1" {
				vResp2, vErr2 := c.transport.Get(ctx, baseURL+"/api/v1/version")
				common.AbsorbTransport(vResp2, &tlsInfo, &redirects)
				if vErr2 == nil && vResp2 != nil {
					vResp = vResp2
					if vResp.StatusCode == http.StatusOK && apiVersion == "" {
						apiVersion = "v1"
					}
				}
			}
			switch vResp.StatusCode {
			case http.StatusOK:
				if vResp.Truncated {
					responseTruncated = true
				} else if vStr, ok := parseChromaVersion(vResp.Body); ok {
					rawVersion = common.BoundString(vStr, 128)
					normVersion = common.NormalizeVersion(vStr)
					verSuccess = true
				}
			case http.StatusUnauthorized, http.StatusForbidden:
				verDenied = true
				if hasChromaDenial(vResp.Header, vResp.Body) {
					chromaConfirmed = true
					deniedConfirmed = true
				}
			}
		} else if verErr == nil && vErr != nil {
			verErr = vErr
		}

		switch {
		case verErr != nil && !chromaConfirmed:
			reason := common.SanitizeError(verErr)
			checks = append(checks, common.CheckEntry{
				CheckID: CheckVersion, Operation: CheckVersion, Outcome: graph.OutcomeFailed,
				Reason: reason, OperationKind: graph.EnumerationOperation,
				Details: map[string]any{"error": reason},
			})
		case chromaConfirmed && verSuccess:
			checks = append(checks, common.CheckEntry{
				CheckID: CheckVersion, Operation: CheckVersion, Outcome: graph.OutcomeSuccess,
				Reason: fmt.Sprintf("ChromaDB %s heartbeat and version %s retrieved", apiVersion, rawVersion), Anonymous: true,
				OperationKind: graph.EnumerationOperation, CountForAccess: false,
				Details: map[string]any{
					"api_version":          apiVersion,
					"software_version":     normVersion,
					"software_version_raw": rawVersion,
				},
			})
		case chromaConfirmed:
			checks = append(checks, common.CheckEntry{
				CheckID: CheckVersion, Operation: CheckVersion, Outcome: graph.OutcomeSuccess,
				Reason: fmt.Sprintf("ChromaDB %s heartbeat confirmed (version unavailable)", apiVersion), Anonymous: true,
				OperationKind: graph.EnumerationOperation, CountForAccess: false,
				Details: map[string]any{"api_version": apiVersion},
			})
		case verDenied:
			checks = append(checks, common.CheckEntry{
				CheckID: CheckVersion, Operation: CheckVersion, Outcome: graph.OutcomeDenied,
				Reason:        "authentication or authorization required for ChromaDB version/heartbeat",
				OperationKind: graph.EnumerationOperation,
			})
		default:
			checks = append(checks, common.CheckEntry{
				CheckID: CheckVersion, Operation: CheckVersion, Outcome: graph.OutcomeFailed,
				Reason:        "target did not return a ChromaDB heartbeat or version",
				OperationKind: graph.EnumerationOperation,
			})
		}
	}

	// 2. Check: GET /api/v2/auth/identity (when v2).
	tenant := "default_tenant"
	database := "default_database"
	var authIdentityExposed bool
	if !chromaConfirmed {
		checks = append(checks, common.CheckEntry{
			CheckID: CheckAuthIdentity, Operation: CheckAuthIdentity, Outcome: graph.OutcomeSkipped,
			Reason: "prerequisite failed: ChromaDB identity not established", OperationKind: graph.EnumerationOperation,
		})
	} else if apiVersion == "v1" {
		checks = append(checks, common.CheckEntry{
			CheckID: CheckAuthIdentity, Operation: CheckAuthIdentity, Outcome: graph.OutcomeUnsupported,
			Reason: "ChromaDB v1 API does not expose /api/v2/auth/identity", OperationKind: graph.EnumerationOperation,
		})
	} else {
		resp, reqErr := c.transport.Get(ctx, baseURL+"/api/v2/auth/identity")
		common.AbsorbTransport(resp, &tlsInfo, &redirects)
		if reqErr != nil {
			reason := common.SanitizeError(reqErr)
			degraded = append(degraded, "auth identity failed: "+reason)
			checks = append(checks, common.CheckEntry{
				CheckID: CheckAuthIdentity, Operation: CheckAuthIdentity, Outcome: graph.OutcomeFailed,
				Reason: reason, OperationKind: graph.EnumerationOperation,
				Details: map[string]any{"error": reason},
			})
		} else {
			switch resp.StatusCode {
			case http.StatusOK:
				var idResp authIdentityResponse
				if err := json.Unmarshal(resp.Body, &idResp); err == nil {
					if strings.TrimSpace(idResp.Tenant) != "" {
						tenant = strings.TrimSpace(idResp.Tenant)
					}
					if len(idResp.Databases) > 0 && strings.TrimSpace(idResp.Databases[0]) != "" {
						database = strings.TrimSpace(idResp.Databases[0])
					}
					authIdentityExposed = true
					checks = append(checks, common.CheckEntry{
						CheckID: CheckAuthIdentity, Operation: CheckAuthIdentity, Outcome: graph.OutcomeSuccess,
						Reason: "ChromaDB auth identity retrieved anonymously", Anonymous: true,
						OperationKind: graph.EnumerationOperation, CountForAccess: false,
						Details: map[string]any{
							"http_status": resp.StatusCode,
							"tenant":      tenant,
							"databases":   idResp.Databases,
						},
					})
				} else {
					checks = append(checks, common.CheckEntry{
						CheckID: CheckAuthIdentity, Operation: CheckAuthIdentity, Outcome: graph.OutcomeFailed,
						Reason: "invalid JSON from /api/v2/auth/identity", OperationKind: graph.EnumerationOperation,
					})
				}
			case http.StatusUnauthorized, http.StatusForbidden:
				checks = append(checks, common.CheckEntry{
					CheckID: CheckAuthIdentity, Operation: CheckAuthIdentity, Outcome: graph.OutcomeDenied,
					Reason:        fmt.Sprintf("HTTP %d: authentication required", resp.StatusCode),
					OperationKind: graph.EnumerationOperation,
					Details:       map[string]any{"http_status": resp.StatusCode},
				})
			default:
				checks = append(checks, common.CheckEntry{
					CheckID: CheckAuthIdentity, Operation: CheckAuthIdentity, Outcome: graph.OutcomeFailed,
					Reason:        fmt.Sprintf("HTTP %d from /api/v2/auth/identity", resp.StatusCode),
					OperationKind: graph.EnumerationOperation,
					Details:       map[string]any{"http_status": resp.StatusCode},
				})
			}
		}
	}

	// 3. Check: Collections inventory.
	var collections []collectionEntry
	var collectionsSuccess, collectionsDenied, collectionsTruncated bool
	var colBasePath string
	if !chromaConfirmed {
		checks = append(checks, common.CheckEntry{
			CheckID: CheckCollections, Operation: CheckCollections, Outcome: graph.OutcomeSkipped,
			Reason: "prerequisite failed: ChromaDB identity not established", OperationKind: graph.EnumerationOperation,
		})
	} else {
		if apiVersion == "v1" {
			colBasePath = "/api/v1/collections"
		} else {
			colBasePath = fmt.Sprintf("/api/v2/tenants/%s/databases/%s/collections", url.PathEscape(tenant), url.PathEscape(database))
		}
		resp, reqErr := c.transport.Get(ctx, baseURL+colBasePath)
		common.AbsorbTransport(resp, &tlsInfo, &redirects)
		if reqErr == nil && resp != nil && resp.StatusCode == http.StatusNotFound && apiVersion != "v1" {
			// Fall back to legacy v1 collections path if v2 route returned 404.
			v1Resp, v1Err := c.transport.Get(ctx, baseURL+"/api/v1/collections")
			common.AbsorbTransport(v1Resp, &tlsInfo, &redirects)
			if v1Err == nil && v1Resp != nil && v1Resp.StatusCode != http.StatusNotFound {
				resp = v1Resp
				reqErr = v1Err
				colBasePath = "/api/v1/collections"
				apiVersion = "v1"
			}
		}

		if reqErr != nil {
			reason := common.SanitizeError(reqErr)
			degraded = append(degraded, "collections check failed: "+reason)
			checks = append(checks, common.CheckEntry{
				CheckID: CheckCollections, Operation: CheckCollections, Outcome: graph.OutcomeFailed,
				Reason: reason, OperationKind: graph.EnumerationOperation,
				Details: map[string]any{"error": reason},
			})
		} else {
			switch resp.StatusCode {
			case http.StatusOK:
				if resp.Truncated {
					responseTruncated = true
					degraded = append(degraded, "collections response truncated at max_response_bytes")
					checks = append(checks, common.CheckEntry{
						CheckID: CheckCollections, Operation: CheckCollections, Outcome: graph.OutcomeFailed,
						Reason: "collections response truncated at max_response_bytes limit", OperationKind: graph.EnumerationOperation,
						Details: map[string]any{"http_status": resp.StatusCode, "truncated": true},
					})
				} else {
					var parsed []collectionEntry
					if err := json.Unmarshal(resp.Body, &parsed); err != nil || parsed == nil {
						degraded = append(degraded, "invalid JSON array from collections")
						checks = append(checks, common.CheckEntry{
							CheckID: CheckCollections, Operation: CheckCollections, Outcome: graph.OutcomeFailed,
							Reason: "invalid JSON array from collections endpoint", OperationKind: graph.EnumerationOperation,
							Details: map[string]any{"http_status": resp.StatusCode},
						})
					} else {
						collectionsSuccess = true
						if len(parsed) > maxItems {
							collectionsTruncated = true
							collections = parsed[:maxItems]
						} else {
							collections = parsed
						}
						checks = append(checks, common.CheckEntry{
							CheckID: CheckCollections, Operation: CheckCollections, Outcome: graph.OutcomeSuccess,
							Reason: "ChromaDB collections enumerated anonymously", Anonymous: true,
							OperationKind: graph.EnumerationOperation, CountForAccess: true,
							Details: map[string]any{
								"http_status":      resp.StatusCode,
								"collection_count": len(collections),
								"truncated":        collectionsTruncated,
							},
						})
					}
				}
			case http.StatusUnauthorized, http.StatusForbidden:
				collectionsDenied = true
				degraded = append(degraded, fmt.Sprintf("collections denied (HTTP %d)", resp.StatusCode))
				checks = append(checks, common.CheckEntry{
					CheckID: CheckCollections, Operation: CheckCollections, Outcome: graph.OutcomeDenied,
					Reason:        fmt.Sprintf("HTTP %d: authentication or authorization required", resp.StatusCode),
					OperationKind: graph.EnumerationOperation,
					Details:       map[string]any{"http_status": resp.StatusCode},
				})
			default:
				degraded = append(degraded, fmt.Sprintf("collections returned HTTP %d", resp.StatusCode))
				checks = append(checks, common.CheckEntry{
					CheckID: CheckCollections, Operation: CheckCollections, Outcome: graph.OutcomeFailed,
					Reason:        fmt.Sprintf("HTTP %d unexpected status", resp.StatusCode),
					OperationKind: graph.EnumerationOperation,
					Details:       map[string]any{"http_status": resp.StatusCode},
				})
			}
		}
	}

	// 4. Check: Per-collection item counts (GET .../collections/<id>/count).
	colCounts := make(map[string]int64, len(collections))
	if !collectionsSuccess {
		checks = append(checks, common.CheckEntry{
			CheckID: CheckCollectionCount, Operation: CheckCollectionCount, Outcome: graph.OutcomeSkipped,
			Reason: "prerequisite failed: collections listing unavailable", OperationKind: graph.EnumerationOperation,
		})
	} else if len(collections) == 0 {
		checks = append(checks, common.CheckEntry{
			CheckID: CheckCollectionCount, Operation: CheckCollectionCount, Outcome: graph.OutcomeSkipped,
			Reason: "no collections available to count", OperationKind: graph.EnumerationOperation,
		})
	} else {
		cntSuccess := 0
		cntDenied := 0
		var cntErrors []string
		for _, col := range collections {
			cid := col.ID
			if cid == "" {
				cid = col.Name
			}
			cURL := baseURL + colBasePath + "/" + url.PathEscape(cid) + "/count"
			resp, reqErr := c.transport.Get(ctx, cURL)
			common.AbsorbTransport(resp, &tlsInfo, &redirects)
			if reqErr != nil {
				cntErrors = append(cntErrors, fmt.Sprintf("%s: %s", col.Name, common.SanitizeError(reqErr)))
				continue
			}
			switch resp.StatusCode {
			case http.StatusOK:
				var n int64
				if err := json.Unmarshal(resp.Body, &n); err != nil {
					if parsedInt, pErr := strconv.ParseInt(strings.TrimSpace(string(resp.Body)), 10, 64); pErr == nil {
						n = parsedInt
					} else {
						cntErrors = append(cntErrors, fmt.Sprintf("%s: invalid count", col.Name))
						continue
					}
				}
				colCounts[cid] = n
				cntSuccess++
			case http.StatusUnauthorized, http.StatusForbidden:
				cntDenied++
				cntErrors = append(cntErrors, fmt.Sprintf("%s: HTTP %d", col.Name, resp.StatusCode))
			default:
				cntErrors = append(cntErrors, fmt.Sprintf("%s: HTTP %d", col.Name, resp.StatusCode))
			}
		}

		switch {
		case cntSuccess > 0:
			checks = append(checks, common.CheckEntry{
				CheckID: CheckCollectionCount, Operation: CheckCollectionCount, Outcome: graph.OutcomeSuccess,
				Reason:        fmt.Sprintf("ChromaDB collection counts retrieved (%d of %d)", cntSuccess, len(collections)),
				Anonymous:     true,
				OperationKind: graph.EnumerationOperation, CountForAccess: true,
				Details: map[string]any{"counted": cntSuccess, "total": len(collections)},
			})
		case cntDenied > 0 && cntDenied == len(collections):
			degraded = append(degraded, "collection count denied")
			checks = append(checks, common.CheckEntry{
				CheckID: CheckCollectionCount, Operation: CheckCollectionCount, Outcome: graph.OutcomeDenied,
				Reason: "authentication required for collection counts", OperationKind: graph.EnumerationOperation,
				Details: map[string]any{"errors": cntErrors},
			})
		default:
			degraded = append(degraded, "collection count failed")
			checks = append(checks, common.CheckEntry{
				CheckID: CheckCollectionCount, Operation: CheckCollectionCount, Outcome: graph.OutcomeFailed,
				Reason: "failed to retrieve collection counts: " + strings.Join(cntErrors, "; "), OperationKind: graph.EnumerationOperation,
				Details: map[string]any{"errors": cntErrors},
			})
		}
	}

	// 5. Check: Bounded document/metadata sampling (POST .../collections/<id>/get without embeddings).
	var contentSummary *graph.ContentSummary
	var contentTruncated bool
	var contentTruncReasons []string
	if !c.cfg.Content.EnabledFor(Surface) {
		checks = append(checks, common.CheckEntry{
			CheckID: CheckDocumentsSample, Operation: CheckDocumentsSample, Outcome: graph.OutcomeSkipped,
			Reason: "content collection disabled by policy", OperationKind: graph.ResourceReadOperation,
			Details: map[string]any{"skipped": true, "policy": "content_disabled"},
		})
	} else if !collectionsSuccess {
		checks = append(checks, common.CheckEntry{
			CheckID: CheckDocumentsSample, Operation: CheckDocumentsSample, Outcome: graph.OutcomeSkipped,
			Reason: "prerequisite failed: collections listing unavailable", OperationKind: graph.ResourceReadOperation,
		})
	} else if len(collections) == 0 {
		checks = append(checks, common.CheckEntry{
			CheckID: CheckDocumentsSample, Operation: CheckDocumentsSample, Outcome: graph.OutcomeSkipped,
			Reason: "no collections available to sample", OperationKind: graph.ResourceReadOperation,
		})
	} else {
		sampleLimit := c.cfg.Content.MaxSamplePoints
		if sampleLimit <= 0 {
			sampleLimit = config.DefaultContentMaxSamplePoints
		}
		reqBody, _ := json.Marshal(getDocsRequest{
			Limit:   sampleLimit,
			Include: []string{"documents", "metadatas"},
		})
		budget := content.NewBudget(c.cfg.Content, secrets.NewRedactor(c.cfg.Secrets))
		getSuccess := 0
		getDenied := 0
		var getErrors []string

		for _, col := range collections {
			cid := col.ID
			if cid == "" {
				cid = col.Name
			}
			getURL := baseURL + colBasePath + "/" + url.PathEscape(cid) + "/get"
			resp, reqErr := c.transport.Post(ctx, getURL, "application/json", reqBody)
			common.AbsorbTransport(resp, &tlsInfo, &redirects)
			if reqErr != nil {
				getErrors = append(getErrors, fmt.Sprintf("%s: %s", col.Name, common.SanitizeError(reqErr)))
				continue
			}
			if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
				getDenied++
				getErrors = append(getErrors, fmt.Sprintf("%s: HTTP %d", col.Name, resp.StatusCode))
				continue
			}
			if resp.StatusCode != http.StatusOK {
				getErrors = append(getErrors, fmt.Sprintf("%s: HTTP %d", col.Name, resp.StatusCode))
				continue
			}
			if resp.Truncated {
				responseTruncated = true
				budget.MarkTruncated(fmt.Sprintf("documents sample for %s truncated at max_response_bytes", col.Name))
				getErrors = append(getErrors, fmt.Sprintf("%s: truncated at max_response_bytes", col.Name))
				continue
			}
			var gd getDocsResponse
			if err := json.Unmarshal(resp.Body, &gd); err != nil {
				getErrors = append(getErrors, fmt.Sprintf("%s: invalid JSON", col.Name))
				continue
			}
			getSuccess++

			var resIDStr string
			if resID, err := graph.NewResourceIdentity(scope, graph.VectorCollection, srvID, col.Name); err == nil {
				resIDStr = resID.ID()
			}
			count := len(gd.Documents)
			if len(gd.Metadatas) > count {
				count = len(gd.Metadatas)
			}
			if count > sampleLimit {
				budget.MarkTruncated(fmt.Sprintf("collection %s truncated at max_sample_points (%d)", col.Name, sampleLimit))
				count = sampleLimit
			}
			for i := 0; i < count; i++ {
				docItem := map[string]any{}
				if i < len(gd.IDs) && gd.IDs[i] != "" {
					docItem["id"] = gd.IDs[i]
				}
				if i < len(gd.Documents) && gd.Documents[i] != nil {
					docItem["document"] = gd.Documents[i]
				}
				if i < len(gd.Metadatas) && gd.Metadatas[i] != nil {
					docItem["metadata"] = gd.Metadatas[i]
				}
				if len(docItem) == 0 {
					continue
				}
				rawSample, _ := json.Marshal(docItem)
				if content.LooksBinary(rawSample) {
					continue
				}
				if ok, _ := budget.ClaimResourceItem(col.Name); !ok {
					break
				}
				docID := fmt.Sprintf("doc-%d", i)
				if i < len(gd.IDs) && gd.IDs[i] != "" {
					docID = gd.IDs[i]
				}
				rec, added, addErr := budget.Add(content.RecordInput{
					DeploymentScope: scope,
					ScanID:          scanID,
					VantageKey:      vantageKey,
					ServiceID:       srvID.ID(),
					ResourceID:      resIDStr,
					Surface:         Surface,
					CheckID:         CheckDocumentsSample,
					Source:          getURL,
					Kind:            content.KindSample,
					Location:        fmt.Sprintf("%s#%s", col.Name, docID),
					MediaType:       "application/json",
					ObservedAt:      obsTime,
					Body:            string(rawSample),
				})
				if addErr != nil {
					return checkpoint.Result{}, fmt.Errorf("create chromadb sample record: %w", addErr)
				}
				if added && c.contentSink != nil {
					if err := c.contentSink.Write(rec); err != nil {
						return checkpoint.Result{}, fmt.Errorf("write chromadb sample record: %w", err)
					}
				}
			}
		}

		contentTruncated = budget.Truncated()
		contentTruncReasons = budget.Reasons()
		contentSummary = common.ContentSummaryFromBudget(budget, obsTime, nil, nil)

		switch {
		case getSuccess > 0:
			details := map[string]any{
				"collections_sampled": getSuccess,
				"content_items":       len(budget.Records()),
				"content_bytes":       budget.Bytes(),
				"content_truncated":   contentTruncated,
			}
			if found := budget.Findings(); len(found) > 0 {
				details["detected_exposures"] = content.ExposureDetails(found)
			}
			checks = append(checks, common.CheckEntry{
				CheckID: CheckDocumentsSample, Operation: CheckDocumentsSample, Outcome: graph.OutcomeSuccess,
				Reason:        fmt.Sprintf("ChromaDB document/metadata samples collected (%d collections)", getSuccess),
				OperationKind: graph.ResourceReadOperation, CountForAccess: false, Details: details,
			})
		case getDenied > 0 && getDenied == len(collections):
			degraded = append(degraded, "document sampling denied")
			checks = append(checks, common.CheckEntry{
				CheckID: CheckDocumentsSample, Operation: CheckDocumentsSample, Outcome: graph.OutcomeDenied,
				Reason: "authentication required for document sampling", OperationKind: graph.ResourceReadOperation,
				Details: map[string]any{"errors": getErrors},
			})
		default:
			degraded = append(degraded, "document sampling failed")
			checks = append(checks, common.CheckEntry{
				CheckID: CheckDocumentsSample, Operation: CheckDocumentsSample, Outcome: graph.OutcomeFailed,
				Reason: "failed to sample documents: " + strings.Join(getErrors, "; "), OperationKind: graph.ResourceReadOperation,
				Details: map[string]any{"errors": getErrors},
			})
		}
	}

	var finalCoverage graph.Coverage
	var finalCoverageReason string
	var finalStatus checkpoint.TargetStatus

	switch {
	case verErr != nil && !chromaConfirmed:
		finalCoverage = graph.CoverageFailed
		finalStatus = checkpoint.TargetStatusFailed
		finalCoverageReason = "target unreachable: " + common.SanitizeError(verErr)
	case !chromaConfirmed:
		finalCoverage = graph.CoverageFailed
		finalStatus = checkpoint.TargetStatusFailed
		finalCoverageReason = "enumeration failed: target not confirmed as ChromaDB"
	case collectionsSuccess:
		if collectionsTruncated || responseTruncated || contentTruncated {
			finalCoverage = graph.CoverageTruncated
			finalStatus = checkpoint.TargetStatusPartial
			finalCoverageReason = chromaTruncationReason(collectionsTruncated, responseTruncated, contentTruncReasons)
		} else if len(degraded) > 0 {
			finalCoverage = graph.CoveragePartial
			finalStatus = checkpoint.TargetStatusPartial
			finalCoverageReason = strings.Join(degraded, "; ")
		} else {
			finalCoverage = graph.CoverageComplete
			finalStatus = checkpoint.TargetStatusCompleted
		}
	case deniedConfirmed && (verDenied || collectionsDenied):
		finalCoverage = graph.CoveragePartial
		finalStatus = checkpoint.TargetStatusPartial
		finalCoverageReason = "authentication required on ChromaDB endpoint"
	default:
		finalCoverage = graph.CoveragePartial
		finalStatus = checkpoint.TargetStatusPartial
		finalCoverageReason = "ChromaDB confirmed, but collection enumeration unavailable or denied"
	}

	obs := graph.Observation{
		SchemaVersion:    "1",
		ScanID:           scanID,
		CollectorVersion: "0.1.0",
		EvidenceID:       evID,
		Source:           baseURL + "/api/v2/heartbeat",
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
			Name:       fmt.Sprintf("ChromaDB · %s:%d", ep.Host(), ep.Port()),
			Product:    "ChromaDB",
			Vendor:     "Chroma",
			VantageKey: vantageKey,
			Access:     access,
			TLS:        common.TLSSummary(tlsInfo),
			Content:    contentSummary,
		}
		if collectionsSuccess {
			facts.CollectionCount = common.IntPtr(len(collections))
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
		if authIdentityExposed {
			srvProps["tenant"] = tenant
			srvProps["database"] = database
		}

		srvNode, err := graph.NewNode(srvID, obs)
		if err != nil {
			return checkpoint.Result{}, fmt.Errorf("create ChromaInstance node: %w", err)
		}
		srvItem, err := emitter.NewNodeItem(srvNode, srvProps)
		if err != nil {
			return checkpoint.Result{}, fmt.Errorf("create ChromaInstance node item: %w", err)
		}
		nodes = append(nodes, srvItem)

		for _, col := range collections {
			key := col.Name
			if key == "" {
				key = col.ID
			}
			if key == "" {
				continue
			}
			colID, err := graph.NewResourceIdentity(scope, graph.VectorCollection, srvID, key)
			if err != nil {
				continue
			}
			colNode, err := graph.NewNode(colID, obs)
			if err != nil {
				continue
			}
			colProps := map[string]any{
				"name":            strings.ToUpper(key),
				"collection_name": key,
			}
			if col.ID != "" {
				colProps["collection_id"] = col.ID
			}
			if col.Tenant != "" {
				colProps["tenant"] = col.Tenant
			}
			if col.Database != "" {
				colProps["database"] = col.Database
			}
			lookupID := col.ID
			if lookupID == "" {
				lookupID = col.Name
			}
			if cnt, ok := colCounts[lookupID]; ok {
				colProps["points_count"] = cnt
			}
			colItem, err := emitter.NewNodeItem(colNode, colProps)
			if err != nil {
				continue
			}
			cEdge, err := graph.NewTopologyEdge(graph.Contains, srvID.Reference(), colID.Reference(), obs)
			if err != nil {
				continue
			}
			nodes = append(nodes, colItem)
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

		method := CheckVersion
		confidence := "exact"
		if !chromaConfirmed || (deniedConfirmed && !collectionsSuccess) {
			method = "denied_response"
			confidence = "inferred"
		}
		fpInput = &evidence.FingerprintInput{
			TargetID:           srvID.ID(),
			Product:            "ChromaDB",
			Vendor:             "Chroma",
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

func isChromaHeartbeat(body []byte) bool {
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return false
	}
	_, ok := doc["nanosecond heartbeat"]
	return ok
}

func parseChromaVersion(body []byte) (string, bool) {
	var v string
	if err := json.Unmarshal(body, &v); err == nil && common.NormalizeVersion(v) != "" {
		return v, true
	}
	trimmed := strings.Trim(strings.TrimSpace(string(body)), `"`)
	if common.NormalizeVersion(trimmed) != "" {
		return trimmed, true
	}
	return "", false
}

func hasChromaDenial(h http.Header, body []byte) bool {
	b := strings.ToLower(string(body))
	www := strings.ToLower(h.Get("Www-Authenticate"))
	return strings.Contains(b, "chroma") || strings.Contains(www, "chroma")
}

func chromaTruncationReason(colTrunc, respTrunc bool, contentReasons []string) string {
	var parts []string
	if colTrunc {
		parts = append(parts, "collection listing truncated at max_items bound")
	}
	if respTrunc {
		parts = append(parts, "response body truncated at max_response_bytes bound")
	}
	parts = append(parts, contentReasons...)
	return strings.Join(parts, "; ")
}
