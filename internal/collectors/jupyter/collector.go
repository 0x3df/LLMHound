package jupyter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/0x3df/LLMHound/internal/checkpoint"
	"github.com/0x3df/LLMHound/internal/config"
	"github.com/0x3df/LLMHound/internal/content"
	"github.com/0x3df/LLMHound/internal/correlate"
	"github.com/0x3df/LLMHound/internal/discovery"
	"github.com/0x3df/LLMHound/internal/emitter"
	"github.com/0x3df/LLMHound/internal/evidence"
	"github.com/0x3df/LLMHound/internal/graph"
	"github.com/0x3df/LLMHound/internal/secrets"
)

// Config configures the Jupyter collector.
type Config struct {
	Scope            string
	VantageKey       string
	ScanID           string
	CollectorVersion string
	Bounds           config.Bounds
	Content          config.Content
	Secrets          config.Secrets
	ContentSink      content.Sink
	Insecure         bool
	UserAgent        string
	Resolver         *correlate.Resolver // nil attaches nothing: every target falls back
	Now              func() time.Time
	HTTPClient       *http.Client // Optional override for testing
}

// Collector performs read-only enumeration of Jupyter notebook servers.
type Collector struct {
	cfg        Config
	httpClient *httpClient
}

// New creates and validates a Jupyter collector instance.
func New(cfg Config) (*Collector, error) {
	if strings.TrimSpace(cfg.Scope) == "" {
		return nil, errors.New("collector requires non-empty deployment scope")
	}
	if strings.TrimSpace(cfg.VantageKey) == "" {
		return nil, errors.New("collector requires non-empty vantage key")
	}
	if strings.TrimSpace(cfg.ScanID) == "" {
		return nil, errors.New("collector requires non-empty scan ID")
	}
	if strings.TrimSpace(cfg.CollectorVersion) == "" {
		cfg.CollectorVersion = "0.1.0"
	}
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}

	var client *httpClient
	if cfg.HTTPClient != nil {
		maxBytes := cfg.Bounds.MaxResponseBytes
		if maxBytes <= 0 {
			maxBytes = 1 << 20
		}
		ua := cfg.UserAgent
		if ua == "" {
			ua = "LLMHound/dev"
		}
		copyClient := *cfg.HTTPClient
		copyClient.CheckRedirect = makeCheckRedirect(cfg.Bounds.MaxRedirects)
		client = &httpClient{
			client:           &copyClient,
			maxResponseBytes: maxBytes,
			userAgent:        ua,
			insecure:         cfg.Insecure,
		}
	} else {
		client = newHTTPClient(cfg.Bounds, cfg.Insecure, cfg.UserAgent)
	}

	return &Collector{
		cfg:        cfg,
		httpClient: client,
	}, nil
}

type checkExecution struct {
	checkID       string
	operation     string
	outcome       graph.Outcome
	reason        string
	anonymous     bool
	operationKind graph.OperationKind
	details       map[string]any
}

// CollectTarget runs allowlisted checks against a target and returns the composite Result.
func (c *Collector) Collect(ctx context.Context, rawTarget string) (checkpoint.Result, error) {
	return c.collect(ctx, rawTarget, true)
}

// CollectIdentified runs allowlisted checks against a target the caller has already
// fingerprinted as Jupyter, without probing it again.
func (c *Collector) CollectIdentified(ctx context.Context, rawTarget string) (checkpoint.Result, error) {
	return c.collect(ctx, rawTarget, false)
}

func (c *Collector) collect(ctx context.Context, rawTarget string, probeFirst bool) (checkpoint.Result, error) {
	if strings.TrimSpace(rawTarget) == "" {
		return checkpoint.Result{}, errors.New("target cannot be empty")
	}

	canonicalURL, err := normalizeTargetURL(rawTarget)
	if err != nil {
		return checkpoint.Result{}, fmt.Errorf("normalize target URL: %w", err)
	}

	ep, err := graph.ParseEndpoint(canonicalURL, "")
	if err != nil {
		return checkpoint.Result{}, fmt.Errorf("parse canonical endpoint: %w", err)
	}

	srvID, err := graph.NewServiceIdentity(c.cfg.Scope, graph.JupyterServer, ep)
	if err != nil {
		return checkpoint.Result{}, fmt.Errorf("create service identity: %w", err)
	}

	obsTime := c.cfg.Now().UTC()
	evidenceID := fmt.Sprintf("ev-%s-%s", c.cfg.ScanID, srvID.ID()[:8])
	baseSource := canonicalURL

	baseObs := graph.Observation{
		SchemaVersion:    "1",
		ScanID:           c.cfg.ScanID,
		CollectorVersion: c.cfg.CollectorVersion,
		EvidenceID:       evidenceID,
		Source:           baseSource,
		Surface:          "jupyter",
		ObservedAt:       obsTime,
		DeploymentScope:  c.cfg.Scope,
		VantageKey:       c.cfg.VantageKey,
		Coverage:         graph.CoverageComplete,
	}

	baseURL := strings.TrimRight(canonicalURL, "/")

	if probeFirst {
		probe, err := discovery.Probe(ctx, c.httpClient.client, baseURL, discovery.JupyterDefinition())
		if err != nil {
			return checkpoint.Result{}, fmt.Errorf("probe target: %w", err)
		}
		if !probe.Matched {
			failedObs := baseObs
			failedObs.Coverage = graph.CoverageFailed
			if probe.Reachable {
				failedObs.CoverageReason = "target not identified as jupyter: " + probe.Reason
			} else {
				failedObs.CoverageReason = "target unreachable: " + probe.Reason
			}
			return checkpoint.Result{
				Target:      rawTarget,
				Surface:     "jupyter",
				Observation: failedObs,
				Status:      checkpoint.TargetStatusFailed,
				Error:       failedObs.CoverageReason,
				Details:     map[string]any{"endpoint": canonicalURL},
			}, nil
		}
	}

	// Track TLS and collected information across checks
	var observedTLS TLSInfo
	var verInfo VersionInfo
	var sessions []CollectedSession
	var files []CollectedFile
	var checks []checkExecution
	var truncatedWorkspace bool
	var truncatedSessions bool
	var skippedDirs int
	var failedChecks []string
	var authRequired bool
	var anyReachable bool

	// 1. Version Check: GET /api
	verCheck := c.executeVersionCheck(ctx, baseURL, srvID.ID())
	checks = append(checks, verCheck.exec)
	if verCheck.reachable {
		anyReachable = true
	}
	if verCheck.tls.Observed {
		observedTLS = verCheck.tls
	}
	if verCheck.authRequired {
		authRequired = true
	}
	if verCheck.exec.outcome == graph.OutcomeFailed {
		failedChecks = append(failedChecks, verCheck.exec.checkID)
	}
	verInfo = verCheck.version

	maxItems := c.cfg.Bounds.MaxItems
	if maxItems <= 0 {
		maxItems = 10000
	}

	tlsBlocked := observedTLS.Observed && observedTLS.VerificationResult == "failed" && !c.cfg.Insecure

	var contentSummary *graph.ContentSummary
	var contentTruncated bool
	var contentTruncReason string

	if tlsBlocked {
		checks = append(checks,
			checkExecution{
				checkID:       CheckIDSessions,
				operation:     OpSessions,
				outcome:       graph.OutcomeSkipped,
				reason:        "prerequisite failed: TLS verification failed",
				operationKind: graph.EnumerationOperation,
			},
			checkExecution{
				checkID:       CheckIDContents,
				operation:     OpContents,
				outcome:       graph.OutcomeSkipped,
				reason:        "prerequisite failed: TLS verification failed",
				operationKind: graph.EnumerationOperation,
			},
			checkExecution{
				checkID:       CheckIDFileContent,
				operation:     OpFileContent,
				outcome:       graph.OutcomeSkipped,
				reason:        "prerequisite failed: TLS verification failed",
				operationKind: graph.ResourceReadOperation,
			},
		)
	} else {
		// 2. Session Metadata Check: GET /api/sessions
		sessCheck := c.executeSessionsCheck(ctx, baseURL, srvID.ID(), maxItems)
		checks = append(checks, sessCheck.exec)
		if sessCheck.reachable {
			anyReachable = true
		}
		if sessCheck.tls.Observed && !observedTLS.Observed {
			observedTLS = sessCheck.tls
		}
		if sessCheck.authRequired {
			authRequired = true
		}
		if sessCheck.exec.outcome == graph.OutcomeFailed {
			failedChecks = append(failedChecks, sessCheck.exec.checkID)
		}
		sessions = sessCheck.sessions
		truncatedSessions = sessCheck.truncated

		// 3. Workspace Listing Check: GET /api/contents
		contCheck := c.executeContentsCheck(ctx, baseURL, srvID.ID(), maxItems)
		checks = append(checks, contCheck.exec)
		if contCheck.reachable {
			anyReachable = true
		}
		if contCheck.tls.Observed && !observedTLS.Observed {
			observedTLS = contCheck.tls
		}
		if contCheck.authRequired {
			authRequired = true
		}
		if contCheck.exec.outcome == graph.OutcomeFailed {
			failedChecks = append(failedChecks, contCheck.exec.checkID)
		}
		if contCheck.truncated {
			truncatedWorkspace = true
		}
		files = contCheck.files
		skippedDirs = contCheck.skippedDirs

		// 4. Content Tier: GET /api/contents/<path>?content=1 (default on, bounded)
		if !c.cfg.Content.EnabledFor("jupyter") {
			checks = append(checks, checkExecution{
				checkID:       CheckIDFileContent,
				operation:     OpFileContent,
				outcome:       graph.OutcomeSkipped,
				reason:        "content collection disabled by policy",
				operationKind: graph.ResourceReadOperation,
				details:       map[string]any{"skipped": true, "policy": "content_disabled"},
			})
		} else if !anyReachable {
			checks = append(checks, checkExecution{
				checkID:       CheckIDFileContent,
				operation:     OpFileContent,
				outcome:       graph.OutcomeSkipped,
				reason:        "prerequisite failed: target unreachable",
				operationKind: graph.ResourceReadOperation,
			})
		} else if contCheck.exec.outcome != graph.OutcomeSuccess {
			checks = append(checks, checkExecution{
				checkID:       CheckIDFileContent,
				operation:     OpFileContent,
				outcome:       graph.OutcomeSkipped,
				reason:        "prerequisite failed: workspace contents listing unavailable",
				operationKind: graph.ResourceReadOperation,
			})
		} else if len(files) == 0 {
			checks = append(checks, checkExecution{
				checkID:       CheckIDFileContent,
				operation:     OpFileContent,
				outcome:       graph.OutcomeSkipped,
				reason:        "no workspace files available to read",
				operationKind: graph.ResourceReadOperation,
			})
		} else {
			fcRes, fcErr := c.executeFileContentCheck(ctx, baseURL, srvID, files, obsTime)
			if fcErr != nil {
				return checkpoint.Result{}, fcErr
			}
			checks = append(checks, fcRes.exec)
			contentSummary = fcRes.summary
			contentTruncated = fcRes.truncated
			contentTruncReason = fcRes.truncateReason
		}
	}

	// Coverage determination
	coverage := graph.CoverageComplete
	coverageReason := ""
	status := checkpoint.TargetStatusCompleted

	if !anyReachable {
		coverage = graph.CoverageFailed
		coverageReason = "target unreachable: connection refused or timeout on all checks"
		status = checkpoint.TargetStatusFailed
	} else if truncatedWorkspace || truncatedSessions {
		coverage = graph.CoverageTruncated
		coverageReason = fmt.Sprintf("listing truncated at max_items limit (%d)", maxItems)
		status = checkpoint.TargetStatusPartial
	} else if contentTruncated {
		coverage = graph.CoverageTruncated
		coverageReason = contentTruncReason
		if coverageReason == "" {
			coverageReason = "workspace content reads truncated at configured bounds"
		}
		status = checkpoint.TargetStatusPartial
	} else if len(failedChecks) > 0 {
		coverage = graph.CoveragePartial
		coverageReason = fmt.Sprintf("checks failed: %s", strings.Join(failedChecks, ", "))
		status = checkpoint.TargetStatusPartial
	} else if skippedDirs > 0 {
		coverage = graph.CoveragePartial
		coverageReason = fmt.Sprintf("root listing only: %d directories not enumerated", skippedDirs)
		status = checkpoint.TargetStatusPartial
	}

	finalObs := baseObs
	finalObs.Coverage = coverage
	finalObs.CoverageReason = coverageReason

	// If unreachable, return honest failed result without constructing fingerprinted nodes
	if !anyReachable {
		var evRecs []evidence.Record
		for _, ch := range checks {
			chkObs := finalObs
			chkObs.EvidenceID = evidenceID + "-" + ch.checkID
			rec, err := evidence.NewCheckResultRecord(graph.CheckResult{
				Observation: chkObs,
				CheckID:     ch.checkID,
				Operation:   ch.operation,
				TargetID:    srvID.ID(),
				Outcome:     ch.outcome,
				Reason:      ch.reason,
			}, ch.details)
			if err == nil {
				evRecs = append(evRecs, rec)
			}
		}
		if observedTLS.Observed {
			tlsObs := finalObs
			tlsObs.EvidenceID = evidenceID + "-tls"
			if tlsRec, err := evidence.NewTLSRecord(evidence.TLSRecordInput{
				Observation:        tlsObs,
				TargetID:           srvID.ID(),
				CertFingerprint:    observedTLS.Fingerprint,
				Issuer:             observedTLS.Issuer,
				Subject:            observedTLS.Subject,
				SANs:               observedTLS.SANs,
				ValidFrom:          observedTLS.ValidFrom,
				ValidTo:            observedTLS.ValidTo,
				VerificationResult: observedTLS.VerificationResult,
				VerificationReason: observedTLS.VerificationReason,
				NegotiatedVersion:  observedTLS.NegotiatedVersion,
				InsecureOverride:   observedTLS.InsecureOverride,
			}); err == nil {
				evRecs = append(evRecs, tlsRec)
			}
		}
		return checkpoint.Result{
			Target:      rawTarget,
			Surface:     "jupyter",
			Observation: finalObs,
			Status:      status,
			Evidence:    evRecs,
			Error:       coverageReason,
			Details: map[string]any{
				"endpoint": canonicalURL,
			},
		}, nil
	}

	// Target was reachable: construct graph nodes, edges, and evidence records
	var nodes []emitter.NodeItem
	var edges []graph.Edge
	var evRecords []evidence.Record

	// Collect unique kernels and session stats
	kernelMap := make(map[string]bool)
	for _, s := range sessions {
		if s.KernelName != "" {
			kernelMap[s.KernelName] = true
		}
	}
	var kernels []string
	for k := range kernelMap {
		kernels = append(kernels, k)
	}
	sort.Strings(kernels)

	// Anonymous access is recorded as flat properties from the enumeration
	// checks only (workspace contents and session listing). Version/API metadata
	// is often readable even when authentication is enabled, so it must not
	// make the service look anonymously accessible.
	var accessEvidence []graph.AccessEvidence
	for _, ch := range checks {
		if ch.checkID != CheckIDContents && ch.checkID != CheckIDSessions {
			continue
		}
		if !(ch.anonymous && ch.outcome == graph.OutcomeSuccess) && ch.outcome != graph.OutcomeDenied {
			continue
		}
		accessEvidence = append(accessEvidence, graph.AccessEvidence{
			Observation:   finalObs,
			CheckID:       ch.checkID,
			Operation:     ch.operation,
			TargetID:      srvID.ID(),
			Outcome:       ch.outcome,
			Reason:        ch.reason,
			Anonymous:     ch.anonymous,
			OperationKind: graph.EnumerationOperation,
		})
	}
	access := graph.SummarizeAccess(accessEvidence)

	// Build JupyterServer node item
	facts := graph.ServiceFacts{
		Endpoint: ep, Name: fmt.Sprintf("Jupyter Server · %s:%d", ep.Host(), ep.Port()),
		Product: "Jupyter Server", Vendor: "Project Jupyter", VantageKey: c.cfg.VantageKey, Access: access,
		// Kernel execution is the product's purpose; inferred from identity, not run.
		ExecSurface: []string{graph.ExecCodeKernel}, ExecSurfaceBasis: graph.BasisInferred,
		Content: contentSummary,
	}
	if observedTLS.Observed {
		facts.TLS = &graph.TLSSummary{
			Result: observedTLS.VerificationResult, Reason: observedTLS.VerificationReason,
			LeafSHA256: observedTLS.Fingerprint, Issuer: observedTLS.Issuer, NotAfter: observedTLS.ValidTo,
			TLSVersion: observedTLS.NegotiatedVersion, InsecureSet: observedTLS.InsecureOverride,
		}
	}
	srvProps := facts.Properties()
	if verInfo.APIVersion != "" {
		srvProps["api_version"] = verInfo.APIVersion
	}
	if verInfo.SoftwareVersion != "" {
		srvProps["software_version"] = verInfo.SoftwareVersion
	}
	if len(kernels) > 0 {
		srvProps["kernels"] = kernels
	}
	srvProps["active_sessions"] = len(sessions)
	srvProps["auth_required"] = authRequired // any observed 401/403 (Jupyter-specific; auth_observed is the cross-surface form)

	srvNode, err := graph.NewNode(srvID, finalObs)
	if err != nil {
		return checkpoint.Result{}, fmt.Errorf("create service node: %w", err)
	}
	srvItem, err := emitter.NewNodeItem(srvNode, srvProps)
	if err != nil {
		return checkpoint.Result{}, fmt.Errorf("create service node item: %w", err)
	}
	nodes = append(nodes, srvItem)

	// Build WorkspaceFile node items and Contains edges
	for _, f := range files {
		fileID, err := graph.NewResourceIdentity(c.cfg.Scope, graph.WorkspaceFile, srvID, f.Path)
		if err != nil {
			continue
		}
		fileNode, err := graph.NewNode(fileID, finalObs)
		if err != nil {
			continue
		}
		fileProps := map[string]any{
			"name":      strings.ToUpper(f.Name),
			"path":      f.Path,
			"file_type": f.Type,
		}
		if f.Size >= 0 {
			fileProps["size"] = f.Size
		}
		if f.LastModified != "" {
			fileProps["last_modified"] = f.LastModified
		}
		fileItem, err := emitter.NewNodeItem(fileNode, fileProps)
		if err != nil {
			return checkpoint.Result{}, fmt.Errorf("create file node item for %q: %w", f.Path, err)
		}
		nodes = append(nodes, fileItem)

		containsEdge, err := graph.NewTopologyEdge(graph.Contains, srvID.Reference(), fileID.Reference(), finalObs)
		if err != nil {
			return checkpoint.Result{}, fmt.Errorf("create contains edge for %q: %w", f.Path, err)
		}
		edges = append(edges, containsEdge)
	}

	// Target correlation: Computer or fallback NetworkEndpoint
	corrObs := finalObs
	corrObs.EvidenceID = evidenceID + "-correlation"
	corrObservedAt, fallbackItem, corrRec, err := c.correlateTarget(ep.Host(), srvID, finalObs, corrObs)
	if err != nil {
		return checkpoint.Result{}, fmt.Errorf("correlate target: %w", err)
	}
	if fallbackItem != nil {
		nodes = append(nodes, *fallbackItem)
	}
	edges = append(edges, corrObservedAt)
	evRecords = append(evRecords, corrRec)

	// Add check result evidence records
	for _, ch := range checks {
		chkObs := finalObs
		chkObs.EvidenceID = evidenceID + "-" + ch.checkID
		if ch.anonymous && ch.outcome == graph.OutcomeSuccess {
			accessEv := graph.AccessEvidence{
				Observation:   chkObs,
				CheckID:       ch.checkID,
				Operation:     ch.operation,
				TargetID:      srvID.ID(),
				Outcome:       ch.outcome,
				Reason:        ch.reason,
				Anonymous:     true,
				OperationKind: ch.operationKind,
			}
			rec, err := evidence.NewAccessEvidenceRecord(accessEv, ch.details)
			if err != nil {
				return checkpoint.Result{}, fmt.Errorf("create access evidence record: %w", err)
			}
			evRecords = append(evRecords, rec)
		} else {
			chkRes := graph.CheckResult{
				Observation: chkObs,
				CheckID:     ch.checkID,
				Operation:   ch.operation,
				TargetID:    srvID.ID(),
				Outcome:     ch.outcome,
				Reason:      ch.reason,
			}
			rec, err := evidence.NewCheckResultRecord(chkRes, ch.details)
			if err != nil {
				return checkpoint.Result{}, fmt.Errorf("create check result record: %w", err)
			}
			evRecords = append(evRecords, rec)
		}
	}

	// Add Fingerprint evidence record if version discovered
	if verInfo.APIVersion != "" || verInfo.SoftwareVersion != "" {
		fpObs := finalObs
		fpObs.EvidenceID = evidenceID + "-fingerprint"
		fpRec, err := evidence.NewFingerprintRecord(evidence.FingerprintInput{
			Observation:        fpObs,
			TargetID:           srvID.ID(),
			Product:            "Jupyter Server",
			Vendor:             "Project Jupyter",
			APIVersion:         verInfo.APIVersion,
			SoftwareVersion:    verInfo.SoftwareVersion,
			SoftwareVersionRaw: verInfo.SoftwareVersion,
			Method:             "api_version",
			Confidence:         "exact",
			Details:            verInfo.Details,
		})
		if err != nil {
			return checkpoint.Result{}, fmt.Errorf("create fingerprint record: %w", err)
		}
		evRecords = append(evRecords, fpRec)
	}

	// Add TLS evidence record if TLS was observed
	if observedTLS.Observed {
		tlsObs := finalObs
		tlsObs.EvidenceID = evidenceID + "-tls"
		tlsRec, err := evidence.NewTLSRecord(evidence.TLSRecordInput{
			Observation:        tlsObs,
			TargetID:           srvID.ID(),
			CertFingerprint:    observedTLS.Fingerprint,
			Issuer:             observedTLS.Issuer,
			Subject:            observedTLS.Subject,
			SANs:               observedTLS.SANs,
			ValidFrom:          observedTLS.ValidFrom,
			ValidTo:            observedTLS.ValidTo,
			VerificationResult: observedTLS.VerificationResult,
			VerificationReason: observedTLS.VerificationReason,
			NegotiatedVersion:  observedTLS.NegotiatedVersion,
			InsecureOverride:   observedTLS.InsecureOverride,
		})
		if err != nil {
			return checkpoint.Result{}, fmt.Errorf("create tls evidence record: %w", err)
		}
		evRecords = append(evRecords, tlsRec)
	}

	result := checkpoint.Result{
		Target:      rawTarget,
		Surface:     "jupyter",
		Observation: finalObs,
		Status:      status,
		Nodes:       nodes,
		Edges:       edges,
		Evidence:    evRecords,
		Details: map[string]any{
			"endpoint":        canonicalURL,
			"auth_required":   authRequired,
			"session_count":   len(sessions),
			"workspace_files": len(files),
		},
	}

	if err := result.Validate(c.cfg.Scope); err != nil {
		return checkpoint.Result{}, fmt.Errorf("validate result: %w", err)
	}

	return result, nil
}

// CollectToJournal performs collection and records the resulting records into the provided journal.
func (c *Collector) CollectToJournal(ctx context.Context, j checkpoint.Journal, rawTarget string) (checkpoint.Result, error) {
	if j == nil {
		return checkpoint.Result{}, errors.New("journal cannot be nil")
	}
	res, err := c.Collect(ctx, rawTarget)
	if err != nil {
		return checkpoint.Result{}, err
	}
	if err := j.RecordResult(res); err != nil {
		return res, fmt.Errorf("record result in journal: %w", err)
	}
	return res, nil
}

type versionCheckResult struct {
	exec         checkExecution
	version      VersionInfo
	tls          TLSInfo
	authRequired bool
	reachable    bool
}

func (c *Collector) executeVersionCheck(ctx context.Context, baseURL, targetID string) versionCheckResult {
	reqURL := baseURL + "/api"
	resp, err := c.httpClient.Get(ctx, reqURL)
	if err != nil {
		var tlsInfo TLSInfo
		if resp != nil {
			tlsInfo = resp.TLS
		}
		return versionCheckResult{
			exec: checkExecution{
				checkID:       CheckIDVersion,
				operation:     OpVersion,
				outcome:       graph.OutcomeFailed,
				reason:        cleanErrorString(err),
				operationKind: graph.EnumerationOperation,
				details:       map[string]any{"url": reqURL, "error": cleanErrorString(err)},
			},
			tls:       tlsInfo,
			reachable: false,
		}
	}

	res := versionCheckResult{
		reachable: true,
		tls:       resp.TLS,
		exec: checkExecution{
			checkID:       CheckIDVersion,
			operation:     OpVersion,
			operationKind: graph.EnumerationOperation,
			details:       map[string]any{"url": reqURL, "status_code": resp.StatusCode},
		},
	}

	// Login page or non-JSON HTML
	if isLoginPage(resp.StatusCode, resp.Body, resp.RedirectURL) {
		res.authRequired = true
		res.exec.outcome = graph.OutcomeDenied
		res.exec.reason = "login page returned instead of api version"
		return res
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		res.authRequired = true
		res.exec.outcome = graph.OutcomeDenied
		res.exec.reason = "authentication required for api metadata"
		return res
	}

	if resp.StatusCode == http.StatusNotFound {
		res.exec.outcome = graph.OutcomeFailed
		res.exec.reason = "api version endpoint not found (404)"
		return res
	}

	if resp.StatusCode != http.StatusOK {
		res.exec.outcome = graph.OutcomeFailed
		res.exec.reason = fmt.Sprintf("unexpected http status %d", resp.StatusCode)
		return res
	}

	var parsed apiVersionResponse
	if err := json.Unmarshal(resp.Body, &parsed); err != nil {
		res.exec.outcome = graph.OutcomeFailed
		res.exec.reason = "malformed json api version response"
		return res
	}

	res.version.APIVersion = parsed.Version
	if parsed.ServerVersion != "" {
		res.version.SoftwareVersion = parsed.ServerVersion
	} else if parsed.JupyterServerVersion != "" {
		res.version.SoftwareVersion = parsed.JupyterServerVersion
	}
	res.version.Details = map[string]any{"raw_version": parsed.Version}

	res.exec.outcome = graph.OutcomeSuccess
	res.exec.reason = "api version reported"
	res.exec.anonymous = true
	res.exec.details["api_version"] = parsed.Version

	return res
}

type sessionsCheckResult struct {
	exec         checkExecution
	sessions     []CollectedSession
	tls          TLSInfo
	authRequired bool
	reachable    bool
	truncated    bool
}

func (c *Collector) executeSessionsCheck(ctx context.Context, baseURL, targetID string, maxItems int) sessionsCheckResult {
	reqURL := baseURL + "/api/sessions"
	resp, err := c.httpClient.Get(ctx, reqURL)
	if err != nil {
		return sessionsCheckResult{
			exec: checkExecution{
				checkID:       CheckIDSessions,
				operation:     OpSessions,
				outcome:       graph.OutcomeFailed,
				reason:        cleanErrorString(err),
				operationKind: graph.EnumerationOperation,
				details:       map[string]any{"url": reqURL, "error": err.Error()},
			},
			reachable: false,
		}
	}

	res := sessionsCheckResult{
		reachable: true,
		tls:       resp.TLS,
		exec: checkExecution{
			checkID:       CheckIDSessions,
			operation:     OpSessions,
			operationKind: graph.EnumerationOperation,
			details:       map[string]any{"url": reqURL, "status_code": resp.StatusCode},
		},
	}

	if isLoginPage(resp.StatusCode, resp.Body, resp.RedirectURL) {
		res.authRequired = true
		res.exec.outcome = graph.OutcomeDenied
		res.exec.reason = "login page returned instead of session list"
		return res
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		res.authRequired = true
		res.exec.outcome = graph.OutcomeDenied
		res.exec.reason = "authentication required for session metadata"
		return res
	}

	if resp.StatusCode == http.StatusNotFound {
		res.exec.outcome = graph.OutcomeFailed
		res.exec.reason = "sessions endpoint not found (404)"
		return res
	}

	if resp.StatusCode != http.StatusOK {
		res.exec.outcome = graph.OutcomeFailed
		res.exec.reason = fmt.Sprintf("unexpected http status %d", resp.StatusCode)
		return res
	}

	var parsed []sessionResponse
	if err := json.Unmarshal(resp.Body, &parsed); err != nil {
		res.exec.outcome = graph.OutcomeFailed
		res.exec.reason = "malformed json session list"
		return res
	}

	for _, s := range parsed {
		if len(res.sessions) >= maxItems {
			res.truncated = true
			break
		}
		cs := CollectedSession{
			ID:   s.ID,
			Path: s.Path,
			Name: s.Name,
			Type: s.Type,
		}
		if s.Kernel != nil {
			cs.KernelName = s.Kernel.Name
			cs.KernelState = s.Kernel.ExecutionState
		}
		res.sessions = append(res.sessions, cs)
	}

	res.exec.outcome = graph.OutcomeSuccess
	res.exec.reason = "session metadata listed anonymously"
	res.exec.anonymous = true
	res.exec.details["session_count"] = len(res.sessions)
	res.exec.details["truncated"] = res.truncated

	return res
}

type contentsCheckResult struct {
	exec         checkExecution
	files        []CollectedFile
	tls          TLSInfo
	authRequired bool
	reachable    bool
	truncated    bool
	skippedDirs  int
}

func (c *Collector) executeContentsCheck(ctx context.Context, baseURL, targetID string, maxItems int) contentsCheckResult {
	reqURL := baseURL + "/api/contents"
	resp, err := c.httpClient.Get(ctx, reqURL)
	if err != nil {
		return contentsCheckResult{
			exec: checkExecution{
				checkID:       CheckIDContents,
				operation:     OpContents,
				outcome:       graph.OutcomeFailed,
				reason:        cleanErrorString(err),
				operationKind: graph.EnumerationOperation,
				details:       map[string]any{"url": reqURL, "error": err.Error()},
			},
			reachable: false,
		}
	}

	res := contentsCheckResult{
		reachable: true,
		tls:       resp.TLS,
		exec: checkExecution{
			checkID:       CheckIDContents,
			operation:     OpContents,
			operationKind: graph.EnumerationOperation,
			details:       map[string]any{"url": reqURL, "status_code": resp.StatusCode},
		},
	}

	if isLoginPage(resp.StatusCode, resp.Body, resp.RedirectURL) {
		res.authRequired = true
		res.exec.outcome = graph.OutcomeDenied
		res.exec.reason = "login page returned instead of contents listing"
		return res
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		res.authRequired = true
		res.exec.outcome = graph.OutcomeDenied
		res.exec.reason = "authentication required for workspace contents"
		return res
	}

	if resp.StatusCode == http.StatusNotFound {
		res.exec.outcome = graph.OutcomeFailed
		res.exec.reason = "contents endpoint not found (404)"
		return res
	}

	if resp.StatusCode != http.StatusOK {
		res.exec.outcome = graph.OutcomeFailed
		res.exec.reason = fmt.Sprintf("unexpected http status %d", resp.StatusCode)
		return res
	}

	var parsed contentsResponse
	if err := json.Unmarshal(resp.Body, &parsed); err != nil {
		res.exec.outcome = graph.OutcomeFailed
		res.exec.reason = "malformed json contents response"
		return res
	}

	for _, item := range parsed.Content {
		// Only notebooks and files are WorkspaceFiles; directories are folder structures
		if item.Type == "directory" {
			res.skippedDirs++
			continue
		}
		if len(res.files) >= maxItems {
			res.truncated = true
			break
		}
		var sz int64 = -1
		if item.Size != nil {
			sz = *item.Size
		}
		f := CollectedFile{
			Name:         item.Name,
			Path:         item.Path,
			Type:         item.Type,
			Size:         sz,
			LastModified: item.LastModified,
		}
		res.files = append(res.files, f)
	}

	res.exec.outcome = graph.OutcomeSuccess
	res.exec.reason = "workspace contents listed anonymously"
	res.exec.anonymous = true
	res.exec.details["workspace_file_count"] = len(res.files)
	res.exec.details["truncated"] = res.truncated
	res.exec.details["directories_not_enumerated"] = res.skippedDirs

	return res
}

type fileContentCheckResult struct {
	exec           checkExecution
	summary        *graph.ContentSummary
	truncated      bool
	truncateReason string
}

func (c *Collector) executeFileContentCheck(ctx context.Context, baseURL string, srvID graph.Identity, files []CollectedFile, obsTime time.Time) (fileContentCheckResult, error) {
	budget := content.NewBudget(c.cfg.Content, secrets.NewRedactor(c.cfg.Secrets))
	var itemsRead, skippedBinary, deniedCount int
	var readErrors []string
	maxReadAttempts := c.cfg.Bounds.MaxItems
	if maxReadAttempts <= 0 {
		maxReadAttempts = 10000
	}
	readAttempts := 0

	for _, f := range files {
		if content.IsBinaryContent(f.Path, "") {
			skippedBinary++
			continue
		}
		escapedPath, ok := escapeJupyterContentPath(f.Path)
		if !ok {
			readErrors = append(readErrors, fmt.Sprintf("%s: invalid workspace path", f.Path))
			continue
		}
		claimed, _ := budget.ClaimResourceItem(f.Path)
		if !claimed {
			continue
		}

		if readAttempts >= maxReadAttempts {
			budget.MarkTruncated(fmt.Sprintf("workspace content reads reached max_items (%d)", maxReadAttempts))
			break
		}
		readAttempts++
		reqURL := baseURL + "/api/contents/" + escapedPath + "?content=1"
		resp, err := c.httpClient.Get(ctx, reqURL)
		if err != nil {
			if errors.Is(err, ErrResponseTooLarge) {
				budget.MarkTruncated(fmt.Sprintf("%s exceeded max_response_bytes", f.Path))
				readErrors = append(readErrors, fmt.Sprintf("%s: response exceeded max_response_bytes", f.Path))
			} else {
				readErrors = append(readErrors, fmt.Sprintf("%s: %s", f.Path, cleanErrorString(err)))
			}
			continue
		}
		if isLoginPage(resp.StatusCode, resp.Body, resp.RedirectURL) || resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			deniedCount++
			readErrors = append(readErrors, fmt.Sprintf("%s: HTTP %d", f.Path, resp.StatusCode))
			continue
		}
		if resp.StatusCode != http.StatusOK {
			readErrors = append(readErrors, fmt.Sprintf("%s: HTTP %d", f.Path, resp.StatusCode))
			continue
		}

		var parsed fileContentResponse
		if err := json.Unmarshal(resp.Body, &parsed); err != nil {
			readErrors = append(readErrors, fmt.Sprintf("%s: malformed json", f.Path))
			continue
		}
		if parsed.Format == "base64" || content.IsBinaryContent(f.Path, parsed.MIMEType) {
			skippedBinary++
			continue
		}
		body, ok := decodeJupyterContentBody(parsed)
		if !ok || body == "" {
			continue
		}
		if content.LooksBinary([]byte(body)) {
			skippedBinary++
			continue
		}

		resID := ""
		if fileID, idErr := graph.NewResourceIdentity(c.cfg.Scope, graph.WorkspaceFile, srvID, f.Path); idErr == nil {
			resID = fileID.ID()
		}
		kind := content.KindWorkspaceFile
		if f.Type == "notebook" || parsed.Type == "notebook" || strings.HasSuffix(strings.ToLower(f.Path), ".ipynb") {
			kind = content.KindNotebook
		}
		rec, added, addErr := budget.Add(content.RecordInput{
			DeploymentScope: c.cfg.Scope,
			ScanID:          c.cfg.ScanID,
			VantageKey:      c.cfg.VantageKey,
			ServiceID:       srvID.ID(),
			ResourceID:      resID,
			Surface:         "jupyter",
			CheckID:         CheckIDFileContent,
			Source:          baseURL + "/api/contents/" + escapedPath,
			Kind:            kind,
			Location:        f.Path,
			MediaType:       parsed.MIMEType,
			ObservedAt:      obsTime,
			Body:            body,
		})
		if addErr != nil {
			return fileContentCheckResult{}, fmt.Errorf("create jupyter content record: %w", addErr)
		}
		if added {
			itemsRead++
			if c.cfg.ContentSink != nil {
				if err := c.cfg.ContentSink.Write(rec); err != nil {
					return fileContentCheckResult{}, fmt.Errorf("write jupyter content record: %w", err)
				}
			}
		}
	}

	details := map[string]any{
		"items_read":     itemsRead,
		"skipped_binary": skippedBinary,
		"content_bytes":  budget.Bytes(),
		"truncated":      budget.Truncated(),
	}
	if len(readErrors) > 0 {
		details["errors"] = readErrors
	}
	if found := budget.Findings(); len(found) > 0 {
		details["detected_exposures"] = content.ExposureDetails(found)
	}

	outcome := graph.OutcomeSuccess
	reason := fmt.Sprintf("read %d workspace item(s) (%d bytes)", itemsRead, budget.Bytes())
	if itemsRead == 0 {
		switch {
		case deniedCount > 0 && deniedCount == len(readErrors):
			outcome = graph.OutcomeDenied
			reason = "authentication required for workspace file contents"
		case len(readErrors) > 0:
			outcome = graph.OutcomeFailed
			reason = strings.Join(readErrors, "; ")
		case skippedBinary > 0:
			reason = fmt.Sprintf("skipped %d binary workspace item(s)", skippedBinary)
		default:
			reason = "workspace items had no text content"
		}
	}

	var summary *graph.ContentSummary
	if itemsRead > 0 || budget.Truncated() {
		summary = &graph.ContentSummary{
			Collected:         true,
			Bytes:             budget.Bytes(),
			Truncated:         budget.Truncated(),
			SecretTypes:       budget.SecretTypes(),
			SecretConfirmedAt: obsTime,
		}
	}

	return fileContentCheckResult{
		exec: checkExecution{
			checkID:       CheckIDFileContent,
			operation:     OpFileContent,
			outcome:       outcome,
			reason:        reason,
			anonymous:     outcome == graph.OutcomeSuccess && itemsRead > 0,
			operationKind: graph.ResourceReadOperation,
			details:       details,
		},
		summary:        summary,
		truncated:      budget.Truncated(),
		truncateReason: strings.Join(budget.Reasons(), "; "),
	}, nil
}

func escapeJupyterContentPath(p string) (string, bool) {
	if p == "" || strings.HasPrefix(p, "/") || strings.ContainsFunc(p, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return "", false
	}
	segs := strings.Split(p, "/")
	escaped := make([]string, 0, len(segs))
	for _, s := range segs {
		if s == "" || s == "." || s == ".." {
			return "", false
		}
		escaped = append(escaped, url.PathEscape(s))
	}
	return strings.Join(escaped, "/"), true
}

func decodeJupyterContentBody(resp fileContentResponse) (string, bool) {
	raw := strings.TrimSpace(string(resp.Content))
	if raw == "" || raw == "null" {
		return "", false
	}
	if strings.HasPrefix(raw, `"`) {
		var s string
		if err := json.Unmarshal([]byte(raw), &s); err == nil {
			return s, true
		}
		return "", false
	}
	if !json.Valid([]byte(raw)) {
		return "", false
	}
	return raw, true
}

func (c *Collector) correlateTarget(host string, srvID graph.Identity, obs, corrObs graph.Observation) (graph.Edge, *emitter.NodeItem, evidence.Record, error) {
	corrRes, err := c.cfg.Resolver.Resolve(c.cfg.Scope, host)
	if err != nil {
		return graph.Edge{}, nil, evidence.Record{}, err
	}
	observedAt, err := corrRes.ObservedAt(srvID, obs)
	if err != nil {
		return graph.Edge{}, nil, evidence.Record{}, err
	}
	corrRec, err := evidence.NewCorrelationRecord(corrRes.Evidence(), corrObs)
	if err != nil {
		return graph.Edge{}, nil, evidence.Record{}, err
	}
	var fallbackItem *emitter.NodeItem
	if fbID, isFallback := corrRes.FallbackIdentity(); isFallback {
		fbNode, err := graph.NewNode(fbID, obs)
		if err != nil {
			return graph.Edge{}, nil, evidence.Record{}, err
		}
		item, err := emitter.NewNodeItem(fbNode, map[string]any{
			"name":         strings.ToUpper(corrRes.Evidence().NormalizedTarget),
			"target_type":  string(corrRes.Evidence().TargetType),
			"target_value": corrRes.Evidence().NormalizedTarget,
		})
		if err != nil {
			return graph.Edge{}, nil, evidence.Record{}, err
		}
		fallbackItem = &item
	}
	return observedAt, fallbackItem, corrRec, nil
}

func normalizeTargetURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if !strings.Contains(raw, "://") {
		if ip, err := netip.ParseAddr(raw); err == nil {
			raw = "http://" + net.JoinHostPort(ip.String(), "8888")
		} else if _, _, err := net.SplitHostPort(raw); err == nil {
			raw = "http://" + raw
		} else {
			raw = "http://" + raw + ":8888"
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.Port() == "" {
		port := "8888"
		if u.Scheme == "https" {
			port = "443"
		}
		u.Host = net.JoinHostPort(u.Hostname(), port)
	}
	return u.String(), nil
}

func isLoginPage(status int, body []byte, redirectURL string) bool {
	if redirectURL != "" {
		if discovery.IsJupyterLoginRedirect(redirectURL) {
			return true
		}
	}
	bodyStr := strings.ToLower(string(body))
	if strings.Contains(bodyStr, `<form action="/login"`) || strings.Contains(bodyStr, `name="password"`) || strings.Contains(bodyStr, `name="token"`) {
		return true
	}
	if strings.Contains(bodyStr, "jupyter notebook") && strings.Contains(bodyStr, "password") {
		return true
	}
	return false
}

func cleanErrorString(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if strings.Contains(msg, "connection refused") {
		return "connection refused"
	}
	if strings.Contains(msg, "deadline exceeded") || strings.Contains(msg, "timeout") {
		return "request timeout"
	}
	if strings.Contains(msg, "no such host") {
		return "host not found"
	}
	return msg
}
