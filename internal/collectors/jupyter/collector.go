package jupyter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/0x3df/LLMHound/internal/checkpoint"
	"github.com/0x3df/LLMHound/internal/config"
	"github.com/0x3df/LLMHound/internal/correlate"
	"github.com/0x3df/LLMHound/internal/emitter"
	"github.com/0x3df/LLMHound/internal/evidence"
	"github.com/0x3df/LLMHound/internal/graph"
)

// Config configures the Jupyter collector.
type Config struct {
	Scope             string
	VantageKey        string
	ScanID            string
	CollectorVersion  string
	Bounds            config.Bounds
	Insecure          bool
	UserAgent         string
	Resolver          *correlate.Resolver
	VerifiedComputers []correlate.Computer
	Now               func() time.Time
	HTTPClient        *http.Client // Optional override for testing
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

	vantageID, err := graph.NewVantageIdentity(c.cfg.Scope, c.cfg.VantageKey)
	if err != nil {
		return checkpoint.Result{}, fmt.Errorf("create vantage identity: %w", err)
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
		Vantage:          vantageID,
		Coverage:         graph.CoverageComplete,
	}

	baseURL := strings.TrimRight(canonicalURL, "/")

	// Track TLS and collected information across checks
	var observedTLS TLSInfo
	var verInfo VersionInfo
	var sessions []CollectedSession
	var files []CollectedFile
	var checks []checkExecution
	var truncatedWorkspace bool
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

	// 2. Session Metadata Check: GET /api/sessions
	sessCheck := c.executeSessionsCheck(ctx, baseURL, srvID.ID())
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

	// 3. Workspace Listing Check: GET /api/contents
	maxItems := c.cfg.Bounds.MaxItems
	if maxItems <= 0 {
		maxItems = 10000
	}
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

	// Coverage determination
	coverage := graph.CoverageComplete
	coverageReason := ""
	status := checkpoint.TargetStatusCompleted

	if !anyReachable {
		coverage = graph.CoverageFailed
		coverageReason = "target unreachable: connection refused or timeout on all checks"
		status = checkpoint.TargetStatusFailed
	} else if truncatedWorkspace {
		coverage = graph.CoverageTruncated
		coverageReason = fmt.Sprintf("workspace listing truncated at max_items limit (%d)", maxItems)
		status = checkpoint.TargetStatusPartial
	} else if len(failedChecks) > 0 {
		coverage = graph.CoveragePartial
		coverageReason = fmt.Sprintf("checks failed: %s", strings.Join(failedChecks, ", "))
		status = checkpoint.TargetStatusPartial
	}

	finalObs := baseObs
	finalObs.Coverage = coverage
	finalObs.CoverageReason = coverageReason

	// If unreachable, return honest failed result without constructing fingerprinted nodes
	if !anyReachable {
		var evRecs []evidence.Record
		for _, ch := range checks {
			rec, err := evidence.NewCheckResultRecord(graph.CheckResult{
				Observation: finalObs,
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

	// Build Vantage node item
	vantageNode, err := graph.NewNode(vantageID, finalObs)
	if err != nil {
		return checkpoint.Result{}, fmt.Errorf("create vantage node: %w", err)
	}
	vantageItem, err := emitter.NewNodeItem(vantageNode, map[string]any{
		"name":        strings.ToUpper(c.cfg.VantageKey),
		"vantage_key": c.cfg.VantageKey,
	})
	if err != nil {
		return checkpoint.Result{}, fmt.Errorf("create vantage node item: %w", err)
	}
	nodes = append(nodes, vantageItem)

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

	// Build JupyterServer node item
	srvProps := map[string]any{
		"name":          fmt.Sprintf("Jupyter Server · %s:%d", ep.Host(), ep.Port()),
		"endpoint_host": ep.Host(),
		"endpoint_port": int(ep.Port()),
		"product":       "Jupyter Server",
		"vendor":        "Project Jupyter",
		"auth_required": authRequired,
	}
	if ep.BasePath() != "" && ep.BasePath() != "/" {
		srvProps["endpoint_path"] = ep.BasePath()
	}
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
			return checkpoint.Result{}, fmt.Errorf("create file identity for %q: %w", f.Path, err)
		}
		fileNode, err := graph.NewNode(fileID, finalObs)
		if err != nil {
			return checkpoint.Result{}, fmt.Errorf("create file node for %q: %w", f.Path, err)
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

	// Check if anonymous access succeeded on an enumeration operation to emit UnauthenticatedAccess edge.
	// Only workspace contents or session listing constitute unauthenticated asset enumeration;
	// version metadata alone does not grant unauthenticated access to the notebook server.
	var anonEnumCheck *checkExecution
	for i := range checks {
		ch := &checks[i]
		if ch.anonymous && ch.outcome == graph.OutcomeSuccess && ch.operationKind == graph.EnumerationOperation {
			if ch.checkID == CheckIDContents {
				anonEnumCheck = ch
				break
			}
			if ch.checkID == CheckIDSessions && anonEnumCheck == nil {
				anonEnumCheck = ch
			}
		}
	}

	if anonEnumCheck != nil {
		accessEv := graph.AccessEvidence{
			Observation:   finalObs,
			CheckID:       anonEnumCheck.checkID,
			Operation:     anonEnumCheck.operation,
			TargetID:      srvID.ID(),
			Outcome:       graph.OutcomeSuccess,
			Reason:        anonEnumCheck.reason,
			Anonymous:     true,
			OperationKind: graph.EnumerationOperation,
		}
		accessEdge, err := graph.NewAccessEdge(graph.UnauthenticatedAccess, vantageID.Reference(), srvID.Reference(), accessEv)
		if err != nil {
			return checkpoint.Result{}, fmt.Errorf("create access edge: %w", err)
		}
		edges = append(edges, accessEdge)
	}

	// Target correlation: Computer or fallback NetworkEndpoint
	corrObservedAt, fallbackItem, corrRec, err := c.correlateTarget(ep.Host(), srvID, finalObs)
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
		if ch.anonymous && ch.outcome == graph.OutcomeSuccess {
			accessEv := graph.AccessEvidence{
				Observation:   finalObs,
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
				Observation: finalObs,
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
		fpRec, err := evidence.NewFingerprintRecord(evidence.FingerprintInput{
			Observation:        finalObs,
			TargetID:           srvID.ID(),
			Product:            "Jupyter Server",
			Vendor:             "Project Jupyter",
			APIVersion:         verInfo.APIVersion,
			SoftwareVersion:    verInfo.SoftwareVersion,
			SoftwareVersionRaw: verInfo.APIVersion,
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
		tlsRec, err := evidence.NewTLSRecord(evidence.TLSRecordInput{
			Observation:        finalObs,
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
		return versionCheckResult{
			exec: checkExecution{
				checkID:       CheckIDVersion,
				operation:     OpVersion,
				outcome:       graph.OutcomeFailed,
				reason:        cleanErrorString(err),
				operationKind: graph.EnumerationOperation,
				details:       map[string]any{"url": reqURL, "error": err.Error()},
			},
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
	if resp.IsHTML || isLoginPage(resp.StatusCode, resp.Body, resp.RedirectURL) {
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
}

func (c *Collector) executeSessionsCheck(ctx context.Context, baseURL, targetID string) sessionsCheckResult {
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

	if resp.IsHTML || isLoginPage(resp.StatusCode, resp.Body, resp.RedirectURL) {
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

	return res
}

type contentsCheckResult struct {
	exec         checkExecution
	files        []CollectedFile
	tls          TLSInfo
	authRequired bool
	reachable    bool
	truncated    bool
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

	if resp.IsHTML || isLoginPage(resp.StatusCode, resp.Body, resp.RedirectURL) {
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

	return res
}

func (c *Collector) correlateTarget(host string, srvID graph.Identity, obs graph.Observation) (graph.Edge, *emitter.NodeItem, evidence.Record, error) {
	if c.cfg.Resolver != nil {
		corrRes, err := c.cfg.Resolver.Resolve(c.cfg.Scope, host, c.cfg.VerifiedComputers)
		if err != nil {
			return graph.Edge{}, nil, evidence.Record{}, err
		}
		observedAt, err := corrRes.ObservedAt(srvID, obs)
		if err != nil {
			return graph.Edge{}, nil, evidence.Record{}, err
		}
		corrRec, err := evidence.NewCorrelationRecord(corrRes.Evidence(), obs)
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
				"name":              strings.ToUpper(corrRes.Evidence().NormalizedTarget),
				"target_type":       string(corrRes.Evidence().TargetType),
				"normalized_target": corrRes.Evidence().NormalizedTarget,
			})
			if err != nil {
				return graph.Edge{}, nil, evidence.Record{}, err
			}
			fallbackItem = &item
		}
		return observedAt, fallbackItem, corrRec, nil
	}

	// Default fallback correlation when no resolver is configured
	target, err := graph.ParseTarget(host)
	if err != nil {
		return graph.Edge{}, nil, evidence.Record{}, err
	}
	fbID, err := graph.NewNetworkEndpointIdentity(c.cfg.Scope, target)
	if err != nil {
		return graph.Edge{}, nil, evidence.Record{}, err
	}
	fbNode, err := graph.NewNode(fbID, obs)
	if err != nil {
		return graph.Edge{}, nil, evidence.Record{}, err
	}
	fbItem, err := emitter.NewNodeItem(fbNode, map[string]any{
		"name":              strings.ToUpper(target.Value()),
		"target_type":       string(target.Type()),
		"normalized_target": target.Value(),
	})
	if err != nil {
		return graph.Edge{}, nil, evidence.Record{}, err
	}

	observedAt, err := graph.NewObservedAtEdge(srvID.Reference(), fbID.Reference(), obs, graph.Correlation{
		MatchValue:     target.Value(),
		FallbackReason: "no_resolver_configured",
	})
	if err != nil {
		return graph.Edge{}, nil, evidence.Record{}, err
	}

	corrRec, err := evidence.NewCorrelationRecord(correlate.Evidence{
		OriginalTarget:   host,
		NormalizedTarget: target.Value(),
		TargetType:       target.Type(),
		Verified:         false,
		Correlation: graph.Correlation{
			MatchValue:     target.Value(),
			FallbackReason: "no_resolver_configured",
		},
	}, obs)
	if err != nil {
		return graph.Edge{}, nil, evidence.Record{}, err
	}

	return observedAt, &fbItem, corrRec, nil
}

func normalizeTargetURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if !strings.Contains(raw, "://") {
		// If no scheme, check if host has port
		if strings.Contains(raw, ":") {
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
		if u.Scheme == "https" {
			u.Host = u.Host + ":443"
		} else {
			u.Host = u.Host + ":8888"
		}
	}
	return u.String(), nil
}

func isLoginPage(status int, body []byte, redirectURL string) bool {
	if redirectURL != "" {
		lowerRedir := strings.ToLower(redirectURL)
		if strings.Contains(lowerRedir, "/login") || strings.Contains(lowerRedir, "/tree") {
			return true
		}
	}
	if status == http.StatusFound || status == http.StatusSeeOther || status == http.StatusTemporaryRedirect {
		return true
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
