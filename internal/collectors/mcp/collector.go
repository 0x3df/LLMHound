package mcp

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
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
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// Target represents an MCP target to collect.
type Target struct {
	URL            string // e.g. "http://127.0.0.1:8080/mcp" or "https://server.corp.local/sse"
	OriginalTarget string // original user-supplied target (e.g. "127.0.0.1:8080")
	Transport      string // "auto" (default), "streamable", "sse"
}

// Option configures the MCP Collector.
type Option func(*Collector)

// WithHTTPClient overrides the base HTTP client transport.
func WithHTTPClient(client *http.Client) Option {
	return func(c *Collector) {
		c.customHTTPClient = client
	}
}

// WithCorrelator provides the asset-mapping resolver used to attach the server
// to an existing BloodHound node. Without one, every target falls back to a
// NetworkEndpoint.
func WithCorrelator(resolver *correlate.Resolver) Option {
	return func(c *Collector) {
		c.correlator = resolver
	}
}

// WithClock sets a deterministic clock for testing.
func WithClock(clock func() time.Time) Option {
	return func(c *Collector) {
		c.clock = clock
	}
}

// WithScanID sets the scan ID.
func WithScanID(scanID string) Option {
	return func(c *Collector) {
		c.scanID = scanID
	}
}

// WithEvidenceID sets the evidence ID.
func WithEvidenceID(evidenceID string) Option {
	return func(c *Collector) {
		c.evidenceID = evidenceID
		c.explicitEvidenceID = true
	}
}

// WithCollectorVersion sets the reported collector version.
func WithCollectorVersion(version string) Option {
	return func(c *Collector) {
		c.collectorVersion = version
	}
}

// WithContentSink configures where bounded content-tier records are written.
func WithContentSink(sink content.Sink) Option {
	return func(c *Collector) {
		c.contentSink = sink
	}
}

// Collector performs anonymous, read-only collection of MCP metadata.
type Collector struct {
	config             config.Config
	customHTTPClient   *http.Client
	correlator         *correlate.Resolver
	contentSink        content.Sink
	clock              func() time.Time
	scanID             string
	evidenceID         string
	explicitEvidenceID bool
	collectorVersion   string
}

// New creates a new MCP Collector.
func New(cfg config.Config, opts ...Option) (*Collector, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	c := &Collector{
		config:           cfg,
		clock:            func() time.Time { return time.Now().UTC() },
		collectorVersion: "0.1.0",
		scanID:           "scan-" + time.Now().UTC().Format("20060102150405"),
		evidenceID:       "ev-" + time.Now().UTC().Format("20060102150405"),
	}

	for _, opt := range opts {
		opt(c)
	}

	return c, nil
}

// Collect evaluates an MCP target and returns a Result.
func (c *Collector) Collect(ctx context.Context, target Target) (*checkpoint.Result, error) {
	return c.collectInternal(ctx, target, c.config.VantageKey, c.config.Scope, c.scanID, c.evidenceID, c.collectorVersion)
}

// CollectTarget evaluates an MCP target and records progress and results into a checkpoint Journal.
func (c *Collector) CollectTarget(ctx context.Context, target Target, j checkpoint.Journal) (*checkpoint.Result, error) {
	scope := c.config.Scope
	scanID := c.scanID
	collectorVersion := c.collectorVersion
	vantageKey := c.config.VantageKey

	if j != nil {
		header := j.Header()
		if header.DeploymentScope != "" {
			scope = header.DeploymentScope
		}
		if header.ScanID != "" {
			scanID = header.ScanID
		}
		if header.CollectorVersion != "" {
			collectorVersion = header.CollectorVersion
		}
		if header.VantageKey != "" {
			vantageKey = header.VantageKey
		}
	}

	origTarget := target.OriginalTarget
	if origTarget == "" {
		origTarget = target.URL
	}

	if j != nil {
		recordErr := j.RecordTarget(checkpoint.TargetRecord{
			Target:  origTarget,
			Surface: "mcp",
			Status:  checkpoint.TargetStatusStarted,
		})
		if recordErr != nil {
			return nil, fmt.Errorf("record target start in journal: %w", recordErr)
		}
	}

	res, err := c.collectInternal(ctx, target, vantageKey, scope, scanID, c.evidenceID, collectorVersion)
	if err != nil {
		if j != nil {
			recordErr := j.RecordTarget(checkpoint.TargetRecord{
				Target:  origTarget,
				Surface: "mcp",
				Status:  checkpoint.TargetStatusFailed,
				Error:   err.Error(),
			})
			if recordErr != nil {
				return nil, fmt.Errorf("%w; record target failure in journal: %v", err, recordErr)
			}
		}
		return nil, err
	}

	if j != nil {
		if recordErr := j.RecordResult(*res); recordErr != nil {
			return nil, fmt.Errorf("record result in journal: %w", recordErr)
		}

		obsRec := checkpoint.ObservationRecord{
			SchemaVersion:    res.Observation.SchemaVersion,
			ScanID:           res.Observation.ScanID,
			CollectorVersion: res.Observation.CollectorVersion,
			EvidenceID:       res.Observation.EvidenceID,
			Source:           res.Observation.Source,
			Surface:          res.Observation.Surface,
			ObservedAt:       res.Observation.ObservedAt.UTC().Format(time.RFC3339),
			VantageKey:       res.Observation.VantageKey,
			Coverage:         string(res.Observation.Coverage),
			CoverageReason:   res.Observation.CoverageReason,
		}

		recordErr := j.RecordTarget(checkpoint.TargetRecord{
			Target:      origTarget,
			Surface:     "mcp",
			Status:      res.Status,
			Observation: &obsRec,
			Error:       res.Error,
		})
		if recordErr != nil {
			return nil, fmt.Errorf("record target result in journal: %w", recordErr)
		}
	}

	return res, nil
}

func (c *Collector) collectInternal(
	ctx context.Context,
	target Target,
	vantageKey string,
	scope string,
	scanID string,
	evidenceID string,
	collectorVersion string,
) (*checkpoint.Result, error) {
	rawURL := target.URL
	if !strings.Contains(rawURL, "://") {
		rawURL = "http://" + rawURL
	}

	ep, err := graph.ParseEndpoint(rawURL, "")
	if err != nil {
		return nil, fmt.Errorf("parse endpoint: %w", err)
	}

	canonicalURL := ep.String()
	origTarget := target.OriginalTarget
	if origTarget == "" {
		origTarget = ep.Host()
	}

	obsTime := c.clock().UTC()

	var baseTransport http.RoundTripper
	if c.customHTTPClient != nil && c.customHTTPClient.Transport != nil {
		baseTransport = c.customHTTPClient.Transport
	} else {
		baseTransport = &http.Transport{
			DialContext:           (&net.Dialer{Timeout: c.config.Bounds.ConnectTimeout}).DialContext,
			TLSHandshakeTimeout:   c.config.Bounds.ConnectTimeout,
			ResponseHeaderTimeout: c.config.Bounds.ResponseTimeout,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: c.config.Insecure,
			},
		}
	}

	tracker := newTrackingTransport(
		baseTransport,
		c.config.Bounds.PerHostRate,
		c.config.Bounds.MaxResponseBytes,
		c.config.UserAgent,
		c.config.Insecure,
		ep.Host(),
	)

	httpClient := buildHTTPClient(
		c.config.Bounds.MaxRedirects,
		tracker,
	)

	srvID, err := graph.NewServiceIdentity(scope, graph.MCPServer, ep)
	if err != nil {
		return nil, fmt.Errorf("create MCPServer identity: %w", err)
	}

	if !c.explicitEvidenceID {
		evidenceID = fmt.Sprintf("ev-%s-%s", scanID, srvID.ID()[:8])
	}

	clientImpl := &mcpsdk.Implementation{
		Name:    "LLMHound",
		Version: collectorVersion,
	}

	mcpClient := mcpsdk.NewClient(clientImpl, nil)

	// Attempt connection with Streamable HTTP or SSE
	session, initResult, connectErr := c.connectTransport(ctx, mcpClient, httpClient, canonicalURL, target.Transport)

	// Extract TLS observation if applicable
	tlsState, tlsErr := tracker.TLSState()
	var tlsObs *tlsObservation
	var evRecords []evidence.Record

	if obs, ok := extractTLSObservation(tlsState, tlsErr, c.config.Insecure); ok {
		tlsObs = &obs
	}

	baseObs := func(cov graph.Coverage, covReason string) graph.Observation {
		return graph.Observation{
			SchemaVersion:    "1",
			ScanID:           scanID,
			CollectorVersion: collectorVersion,
			EvidenceID:       evidenceID,
			Source:           canonicalURL,
			Surface:          "mcp",
			ObservedAt:       obsTime,
			DeploymentScope:  scope,
			VantageKey:       vantageKey,
			Coverage:         cov,
			CoverageReason:   covReason,
		}
	}

	var checks []graph.CheckResult
	var checkDetails = make(map[string]map[string]any)

	addCheck := func(checkID, op, reason string, outcome graph.Outcome, details map[string]any, obs graph.Observation) {
		cr := graph.CheckResult{
			Observation: obs,
			CheckID:     checkID,
			Operation:   op,
			TargetID:    srvID.ID(),
			Outcome:     outcome,
			Reason:      reason,
		}
		checks = append(checks, cr)
		if details != nil {
			checkDetails[checkID] = details
		}
	}

	// Case 1: TLS verification failure
	if tlsObs != nil && tlsObs.VerificationResult == "failed" && !c.config.Insecure {
		failReason := "TLS certificate verification failed: " + tlsObs.VerificationReason
		obs := baseObs(graph.CoverageFailed, failReason)

		addCheck(CheckIDInitialize, OpInitialize, failReason, graph.OutcomeFailed, map[string]any{"tls_error": tlsObs.VerificationReason}, obs)
		addCheck(CheckIDToolsList, OpToolsList, "prerequisite failed: TLS verification failed", graph.OutcomeSkipped, nil, obs)
		addCheck(CheckIDResourcesList, OpResourcesList, "prerequisite failed: TLS verification failed", graph.OutcomeSkipped, nil, obs)
		addCheck(CheckIDResourcesRead, OpResourcesRead, "prerequisite failed: TLS verification failed", graph.OutcomeSkipped, nil, obs)
		addCheck(CheckIDPromptsList, OpPromptsList, "prerequisite failed: TLS verification failed", graph.OutcomeSkipped, nil, obs)
		addCheck(CheckIDRFC9728, OpRFC9728, "prerequisite failed: TLS verification failed", graph.OutcomeSkipped, nil, obs)

		recs, err := c.buildEvidenceRecords(srvID.ID(), checks, checkDetails, nil, tlsObs, tracker.Redirects(), nil, obs)
		if err != nil {
			return nil, err
		}
		evRecords = append(evRecords, recs...)

		return &checkpoint.Result{
			Target:      origTarget,
			Surface:     "mcp",
			Observation: obs,
			Status:      checkpoint.TargetStatusFailed,
			Evidence:    evRecords,
			Error:       failReason,
		}, nil
	}

	lastCode, _ := tracker.LastStatus()

	// Case 2: Authentication Required (401)
	if lastCode == http.StatusUnauthorized || (connectErr != nil && strings.Contains(connectErr.Error(), "Unauthorized")) {
		denyReason := "authentication required (HTTP 401)"
		obs := baseObs(graph.CoverageFailed, denyReason)

		addCheck(CheckIDInitialize, OpInitialize, denyReason, graph.OutcomeDenied, map[string]any{"http_status": 401}, obs)

		// Trigger RFC 9728 protected-resource metadata check
		rfcCtx, rfcCancel := callTimeout(ctx, c.config.Bounds.ResponseTimeout)
		authServers, resource, rfcCode, rfcErr := executeRFC9728(rfcCtx, httpClient, canonicalURL, c.config.Bounds.MaxResponseBytes)
		rfcCancel()
		if rfcErr == nil && len(authServers) > 0 {
			addCheck(CheckIDRFC9728, OpRFC9728, "discovered RFC 9728 protected resource metadata", graph.OutcomeSuccess, map[string]any{
				"oauth_servers": authServers,
				"resource":      resource,
				"http_status":   rfcCode,
			}, obs)
		} else {
			reason := fmt.Sprintf("RFC 9728 endpoint returned HTTP %d", rfcCode)
			if rfcErr != nil {
				reason = fmt.Sprintf("RFC 9728 lookup failed: %v", rfcErr)
			}
			addCheck(CheckIDRFC9728, OpRFC9728, reason, graph.OutcomeFailed, map[string]any{"http_status": rfcCode}, obs)
		}

		addCheck(CheckIDToolsList, OpToolsList, "prerequisite failed: server requires authentication", graph.OutcomeSkipped, nil, obs)
		addCheck(CheckIDResourcesList, OpResourcesList, "prerequisite failed: server requires authentication", graph.OutcomeSkipped, nil, obs)
		addCheck(CheckIDResourcesRead, OpResourcesRead, "prerequisite failed: server requires authentication", graph.OutcomeSkipped, nil, obs)
		addCheck(CheckIDPromptsList, OpPromptsList, "prerequisite failed: server requires authentication", graph.OutcomeSkipped, nil, obs)

		recs, err := c.buildEvidenceRecords(srvID.ID(), checks, checkDetails, nil, tlsObs, tracker.Redirects(), nil, obs)
		if err != nil {
			return nil, err
		}
		evRecords = append(evRecords, recs...)

		return &checkpoint.Result{
			Target:      origTarget,
			Surface:     "mcp",
			Observation: obs,
			Status:      checkpoint.TargetStatusFailed,
			Evidence:    evRecords,
			Error:       denyReason,
		}, nil
	}

	// Case 3: Access Forbidden (403)
	if lastCode == http.StatusForbidden || (connectErr != nil && strings.Contains(connectErr.Error(), "Forbidden")) {
		denyReason := "access forbidden (HTTP 403)"
		obs := baseObs(graph.CoverageFailed, denyReason)

		addCheck(CheckIDInitialize, OpInitialize, denyReason, graph.OutcomeDenied, map[string]any{"http_status": 403}, obs)
		addCheck(CheckIDToolsList, OpToolsList, "prerequisite failed: access forbidden", graph.OutcomeSkipped, nil, obs)
		addCheck(CheckIDResourcesList, OpResourcesList, "prerequisite failed: access forbidden", graph.OutcomeSkipped, nil, obs)
		addCheck(CheckIDResourcesRead, OpResourcesRead, "prerequisite failed: access forbidden", graph.OutcomeSkipped, nil, obs)
		addCheck(CheckIDPromptsList, OpPromptsList, "prerequisite failed: access forbidden", graph.OutcomeSkipped, nil, obs)
		addCheck(CheckIDRFC9728, OpRFC9728, "not applicable; endpoint returned 403 not 401", graph.OutcomeSkipped, nil, obs)

		recs, err := c.buildEvidenceRecords(srvID.ID(), checks, checkDetails, nil, tlsObs, tracker.Redirects(), nil, obs)
		if err != nil {
			return nil, err
		}
		evRecords = append(evRecords, recs...)

		return &checkpoint.Result{
			Target:      origTarget,
			Surface:     "mcp",
			Observation: obs,
			Status:      checkpoint.TargetStatusFailed,
			Evidence:    evRecords,
			Error:       denyReason,
		}, nil
	}

	// Case 4: Other connection / transport failure
	if connectErr != nil {
		failReason := fmt.Sprintf("failed to connect to MCP endpoint: %v", connectErr)
		obs := baseObs(graph.CoverageFailed, failReason)

		addCheck(CheckIDInitialize, OpInitialize, failReason, graph.OutcomeFailed, map[string]any{"error": connectErr.Error()}, obs)
		addCheck(CheckIDToolsList, OpToolsList, "prerequisite failed: endpoint unreachable", graph.OutcomeSkipped, nil, obs)
		addCheck(CheckIDResourcesList, OpResourcesList, "prerequisite failed: endpoint unreachable", graph.OutcomeSkipped, nil, obs)
		addCheck(CheckIDResourcesRead, OpResourcesRead, "prerequisite failed: endpoint unreachable", graph.OutcomeSkipped, nil, obs)
		addCheck(CheckIDPromptsList, OpPromptsList, "prerequisite failed: endpoint unreachable", graph.OutcomeSkipped, nil, obs)
		addCheck(CheckIDRFC9728, OpRFC9728, "not applicable; endpoint connection failed", graph.OutcomeSkipped, nil, obs)

		recs, err := c.buildEvidenceRecords(srvID.ID(), checks, checkDetails, nil, tlsObs, tracker.Redirects(), nil, obs)
		if err != nil {
			return nil, err
		}
		evRecords = append(evRecords, recs...)

		return &checkpoint.Result{
			Target:      origTarget,
			Surface:     "mcp",
			Observation: obs,
			Status:      checkpoint.TargetStatusFailed,
			Evidence:    evRecords,
			Error:       failReason,
		}, nil
	}

	defer session.Close()

	// Initialize succeeded anonymously!
	initSuccessReason := "server initialized anonymously without credentials"

	// RFC 9728 is skipped because no 401 occurred
	rfc9728Reason := "not applicable; endpoint did not require authentication"

	// Enumerate tools
	var tools []*mcpsdk.Tool
	var toolsTruncated bool
	var toolsTruncReason string
	var toolsErr error

	if initResult.Capabilities == nil || initResult.Capabilities.Tools == nil {
		// Capability not advertised
	} else {
		tools, toolsTruncated, toolsTruncReason, toolsErr = executeToolsList(ctx, session, c.config.Bounds.MaxPages, c.config.Bounds.MaxItems, c.config.Bounds.ResponseTimeout)
	}

	// Enumerate resources (descriptors only, never content!)
	var resources []*mcpsdk.Resource
	var templates []*mcpsdk.ResourceTemplate
	var resTruncated bool
	var resTruncReason string
	var resErr error
	var templatesErr error

	if initResult.Capabilities == nil || initResult.Capabilities.Resources == nil {
		// Capability not advertised
	} else {
		resources, templates, resTruncated, resTruncReason, resErr, templatesErr = executeResourcesList(ctx, session, c.config.Bounds.MaxPages, c.config.Bounds.MaxItems, c.config.Bounds.ResponseTimeout)
	}

	// Enumerate prompts
	var prompts []*mcpsdk.Prompt
	var promptsTruncated bool
	var promptsTruncReason string
	var promptsErr error

	if initResult.Capabilities == nil || initResult.Capabilities.Prompts == nil {
		// Capability not advertised
	} else {
		prompts, promptsTruncated, promptsTruncReason, promptsErr = executePromptsList(ctx, session, c.config.Bounds.MaxPages, c.config.Bounds.MaxItems, c.config.Bounds.ResponseTimeout)
	}

	// Content tier: read listed concrete resources (never templates, never binary blobs)
	var contentSummary *graph.ContentSummary
	var contentTruncated bool
	var contentTruncReason string
	var contentDegraded bool
	var contentDegradeReason string
	var resReadOutcome graph.Outcome
	var resReadReason string
	var resReadDetails map[string]any
	switch {
	case !c.config.Content.EnabledFor("mcp"):
		resReadOutcome = graph.OutcomeSkipped
		resReadReason = "content collection disabled by policy"
		resReadDetails = map[string]any{"skipped": true, "policy": "content_disabled"}
	case initResult.Capabilities == nil || initResult.Capabilities.Resources == nil:
		resReadOutcome = graph.OutcomeSkipped
		resReadReason = "server does not advertise resources capability"
	case resErr != nil:
		resReadOutcome = graph.OutcomeSkipped
		resReadReason = "prerequisite failed: resources/list did not succeed"
	case len(resources) == 0:
		resReadOutcome = graph.OutcomeSkipped
		resReadReason = "no concrete resources available to read"
	default:
		rr, err := c.readMCPResources(ctx, session, srvID, scope, scanID, vantageKey, canonicalURL, obsTime, resources)
		if err != nil {
			return nil, err
		}
		resReadOutcome = rr.outcome
		resReadReason = rr.reason
		resReadDetails = rr.details
		contentSummary = rr.summary
		contentTruncated = rr.truncated
		contentTruncReason = rr.truncateReason
		contentDegraded = rr.degraded
		contentDegradeReason = rr.degradeReason
	}

	// Determine surface coverage
	var finalCoverage graph.Coverage
	var finalCoverageReason string

	if toolsTruncated || resTruncated || promptsTruncated || contentTruncated {
		finalCoverage = graph.CoverageTruncated
		var reasons []string
		if toolsTruncReason != "" {
			reasons = append(reasons, toolsTruncReason)
		}
		if resTruncReason != "" {
			reasons = append(reasons, resTruncReason)
		}
		if promptsTruncReason != "" {
			reasons = append(reasons, promptsTruncReason)
		}
		if contentTruncReason != "" {
			reasons = append(reasons, contentTruncReason)
		}
		finalCoverageReason = strings.Join(reasons, "; ")
	} else if toolsErr != nil || resErr != nil || templatesErr != nil || promptsErr != nil || contentDegraded {
		finalCoverage = graph.CoveragePartial
		var reasons []string
		if toolsErr != nil {
			reasons = append(reasons, "tools/list: "+toolsErr.Error())
		}
		if resErr != nil {
			reasons = append(reasons, "resources/list: "+resErr.Error())
		}
		if templatesErr != nil {
			reasons = append(reasons, "resources/templates/list: "+templatesErr.Error())
		}
		if promptsErr != nil {
			reasons = append(reasons, "prompts/list: "+promptsErr.Error())
		}
		if contentDegradeReason != "" {
			reasons = append(reasons, "resources/read: "+contentDegradeReason)
		}
		finalCoverageReason = strings.Join(reasons, "; ")
	} else {
		finalCoverage = graph.CoverageComplete
	}

	finalObs := baseObs(finalCoverage, finalCoverageReason)

	// Populate CheckResults with final observation
	addCheck(CheckIDInitialize, OpInitialize, initSuccessReason, graph.OutcomeSuccess, map[string]any{"protocol_version": initResult.ProtocolVersion}, finalObs)
	addCheck(CheckIDRFC9728, OpRFC9728, rfc9728Reason, graph.OutcomeSkipped, nil, finalObs)

	if initResult.Capabilities == nil || initResult.Capabilities.Tools == nil {
		addCheck(CheckIDToolsList, OpToolsList, "server does not advertise tools capability", graph.OutcomeSkipped, nil, finalObs)
	} else if toolsErr != nil {
		outcome, reason := classifyRPCError(toolsErr, OpToolsList)
		addCheck(CheckIDToolsList, OpToolsList, reason, outcome, map[string]any{"error": toolsErr.Error()}, finalObs)
	} else {
		details := map[string]any{"items_count": len(tools)}
		if toolsTruncated {
			details["truncated"] = true
			details["truncation_reason"] = toolsTruncReason
		}
		addCheck(CheckIDToolsList, OpToolsList, "tools enumerated successfully", graph.OutcomeSuccess, details, finalObs)
	}

	if initResult.Capabilities == nil || initResult.Capabilities.Resources == nil {
		addCheck(CheckIDResourcesList, OpResourcesList, "server does not advertise resources capability", graph.OutcomeSkipped, nil, finalObs)
	} else if resErr != nil {
		outcome, reason := classifyRPCError(resErr, OpResourcesList)
		addCheck(CheckIDResourcesList, OpResourcesList, reason, outcome, map[string]any{"error": resErr.Error()}, finalObs)
	} else {
		details := map[string]any{"items_count": len(resources), "templates_count": len(templates)}
		if resTruncated {
			details["truncated"] = true
			details["truncation_reason"] = resTruncReason
		}
		reason := "resources enumerated successfully"
		if templatesErr != nil {
			details["partial"] = true
			details["templates_error"] = templatesErr.Error()
			reason = "concrete resources enumerated; resource template enumeration failed"
		}
		addCheck(CheckIDResourcesList, OpResourcesList, reason, graph.OutcomeSuccess, details, finalObs)
	}

	addCheck(CheckIDResourcesRead, OpResourcesRead, resReadReason, resReadOutcome, resReadDetails, finalObs)

	if initResult.Capabilities == nil || initResult.Capabilities.Prompts == nil {
		addCheck(CheckIDPromptsList, OpPromptsList, "server does not advertise prompts capability", graph.OutcomeSkipped, nil, finalObs)
	} else if promptsErr != nil {
		outcome, reason := classifyRPCError(promptsErr, OpPromptsList)
		addCheck(CheckIDPromptsList, OpPromptsList, reason, outcome, map[string]any{"error": promptsErr.Error()}, finalObs)
	} else {
		details := map[string]any{"items_count": len(prompts)}
		if promptsTruncated {
			details["truncated"] = true
			details["truncation_reason"] = promptsTruncReason
		}
		addCheck(CheckIDPromptsList, OpPromptsList, "prompts enumerated successfully", graph.OutcomeSuccess, details, finalObs)
	}

	// Build graph nodes and edges
	var nodes []emitter.NodeItem
	var edges []graph.Edge

	// Anonymous access is recorded as flat server properties, never as edges.
	// No credentials are ever sent, so every successful enumeration check is anonymous.
	var accessEvidence []graph.AccessEvidence
	for _, ch := range checks {
		if ch.CheckID == CheckIDResourcesRead {
			continue
		}
		if ch.Outcome != graph.OutcomeSuccess && ch.Outcome != graph.OutcomeDenied {
			continue
		}
		accessEvidence = append(accessEvidence, graph.AccessEvidence{
			Observation:   finalObs,
			CheckID:       ch.CheckID,
			Operation:     ch.Operation,
			TargetID:      srvID.ID(),
			Outcome:       ch.Outcome,
			Reason:        ch.Reason,
			Anonymous:     ch.Outcome == graph.OutcomeSuccess,
			OperationKind: graph.EnumerationOperation,
		})
	}
	access := graph.SummarizeAccess(accessEvidence)

	// 1. Server node
	srvNode, err := buildServerNode(srvID, ep, finalObs, initResult, tlsObs, access, contentSummary)
	if err != nil {
		return nil, fmt.Errorf("build MCPServer node: %w", err)
	}
	nodes = append(nodes, srvNode)

	// 2. Tool nodes and ProvidesTool edges
	toolNodes, toolEdges, err := buildToolNodesAndEdges(scope, srvID, finalObs, tools)
	if err != nil {
		return nil, fmt.Errorf("build tool nodes/edges: %w", err)
	}
	nodes = append(nodes, toolNodes...)
	edges = append(edges, toolEdges...)

	// 3. Resource nodes and ProvidesResource edges
	resNodes, resEdges, err := buildResourceNodesAndEdges(scope, srvID, finalObs, resources, templates)
	if err != nil {
		return nil, fmt.Errorf("build resource nodes/edges: %w", err)
	}
	nodes = append(nodes, resNodes...)
	edges = append(edges, resEdges...)

	// 4. Prompt nodes and ProvidesPrompt edges
	promptNodes, promptEdges, err := buildPromptNodesAndEdges(scope, srvID, finalObs, prompts)
	if err != nil {
		return nil, fmt.Errorf("build prompt nodes/edges: %w", err)
	}
	nodes = append(nodes, promptNodes...)
	edges = append(edges, promptEdges...)

	// 5. Attachment: existing native node from the asset mapping, else NetworkEndpoint
	observedAtEdge, fallbackNode, corrEv, err := buildCorrelationEdgeAndFallback(
		scope,
		ep.Host(),
		srvID,
		finalObs,
		c.correlator,
	)
	if err != nil {
		return nil, fmt.Errorf("build correlation edge: %w", err)
	}
	edges = append(edges, observedAtEdge)
	if fallbackNode != nil {
		nodes = append(nodes, *fallbackNode)
	}

	// 6. Fingerprint input
	var fpInput *evidence.FingerprintInput
	if initResult != nil && initResult.ServerInfo != nil {
		fp := evidence.FingerprintInput{
			Observation:        finalObs,
			TargetID:           srvID.ID(),
			Product:            initResult.ServerInfo.Name,
			SoftwareVersionRaw: initResult.ServerInfo.Version,
			ProtocolVersion:    initResult.ProtocolVersion,
			Method:             OpInitialize,
			Confidence:         "observed",
			Details: map[string]any{
				"capabilities": extractCapabilities(initResult.Capabilities),
			},
		}
		fpInput = &fp
	}

	recs, err := c.buildEvidenceRecords(srvID.ID(), checks, checkDetails, fpInput, tlsObs, tracker.Redirects(), &corrEv, finalObs)
	if err != nil {
		return nil, err
	}
	evRecords = append(evRecords, recs...)

	targetStatus := checkpoint.TargetStatusCompleted
	if finalCoverage != graph.CoverageComplete {
		targetStatus = checkpoint.TargetStatusPartial
	}

	return &checkpoint.Result{
		Target:      origTarget,
		Surface:     "mcp",
		Observation: finalObs,
		Status:      targetStatus,
		Nodes:       nodes,
		Edges:       edges,
		Evidence:    evRecords,
		Error:       finalCoverageReason,
	}, nil
}

func (c *Collector) connectTransport(
	ctx context.Context,
	mcpClient *mcpsdk.Client,
	httpClient *http.Client,
	endpointURL string,
	preferredTransport string,
) (*mcpsdk.ClientSession, *mcpsdk.InitializeResult, error) {
	trySSE := func(url string) (*mcpsdk.ClientSession, *mcpsdk.InitializeResult, error) {
		t := &mcpsdk.SSEClientTransport{
			Endpoint:   url,
			HTTPClient: httpClient,
		}
		s, err := mcpClient.Connect(ctx, t, nil)
		if err != nil {
			return nil, nil, err
		}
		return s, s.InitializeResult(), nil
	}

	tryStreamable := func(url string) (*mcpsdk.ClientSession, *mcpsdk.InitializeResult, error) {
		t := &mcpsdk.StreamableClientTransport{
			Endpoint:             url,
			HTTPClient:           httpClient,
			DisableStandaloneSSE: true,
		}
		s, err := mcpClient.Connect(ctx, t, nil)
		if err != nil {
			return nil, nil, err
		}
		return s, s.InitializeResult(), nil
	}

	if preferredTransport == "sse" || (preferredTransport != "streamable" && strings.HasSuffix(endpointURL, "/sse")) {
		s, initRes, err := trySSE(endpointURL)
		if err == nil {
			return s, initRes, nil
		}
		if preferredTransport == "sse" {
			return nil, nil, err
		}
	}

	// Try Streamable HTTP
	s, initRes, streamableErr := tryStreamable(endpointURL)
	if streamableErr == nil {
		return s, initRes, nil
	}

	// Check if Streamable failed due to auth denial or TLS verification error; do not fall back in those cases
	errStr := streamableErr.Error()
	if strings.Contains(errStr, "Unauthorized") || strings.Contains(errStr, "Forbidden") ||
		strings.Contains(errStr, "401") || strings.Contains(errStr, "403") ||
		isTLSError(streamableErr) {
		return nil, nil, streamableErr
	}

	// Fallback to SSE if auto
	if preferredTransport == "" || preferredTransport == "auto" {
		sseURL := endpointURL
		if !strings.HasSuffix(sseURL, "/sse") {
			sseURL = strings.TrimSuffix(sseURL, "/") + "/sse"
		}
		s, initRes, sseErr := trySSE(sseURL)
		if sseErr == nil {
			return s, initRes, nil
		}
	}

	return nil, nil, streamableErr
}

func (c *Collector) buildEvidenceRecords(
	targetID string,
	checks []graph.CheckResult,
	checkDetails map[string]map[string]any,
	fpInput *evidence.FingerprintInput,
	tlsObs *tlsObservation,
	redirects []redirectInfo,
	corrEv *correlate.Evidence,
	obs graph.Observation,
) ([]evidence.Record, error) {
	var records []evidence.Record

	for _, check := range checks {
		checkObs := obs
		checkObs.EvidenceID = fmt.Sprintf("%s-%s", obs.EvidenceID, check.CheckID)
		check.Observation = checkObs
		details := checkDetails[check.CheckID]
		if check.CheckID == CheckIDInitialize && check.Outcome == graph.OutcomeSuccess {
			// Record AccessEvidence record for initialize
			accEv := graph.AccessEvidence{
				Observation:   checkObs,
				CheckID:       check.CheckID,
				Operation:     check.Operation,
				TargetID:      check.TargetID,
				Outcome:       check.Outcome,
				Reason:        check.Reason,
				Anonymous:     true,
				OperationKind: graph.EnumerationOperation,
			}
			rec, err := evidence.NewAccessEvidenceRecord(accEv, details)
			if err != nil {
				return nil, fmt.Errorf("build AccessEvidence evidence record: %w", err)
			}
			records = append(records, rec)
		} else {
			rec, err := evidence.NewCheckResultRecord(check, details)
			if err != nil {
				return nil, fmt.Errorf("build CheckResult evidence record: %w", err)
			}
			records = append(records, rec)
		}
	}

	if fpInput != nil {
		fpObs := obs
		fpObs.EvidenceID = fmt.Sprintf("%s-fingerprint", obs.EvidenceID)
		fpInput.Observation = fpObs
		rec, err := evidence.NewFingerprintRecord(*fpInput)
		if err != nil {
			return nil, fmt.Errorf("build Fingerprint evidence record: %w", err)
		}
		records = append(records, rec)
	}

	if tlsObs != nil {
		tlsObsRecord := obs
		tlsObsRecord.EvidenceID = fmt.Sprintf("%s-tls", obs.EvidenceID)
		tlsInput := evidence.TLSRecordInput{
			Observation:        tlsObsRecord,
			TargetID:           targetID,
			CertFingerprint:    tlsObs.CertFingerprint,
			Issuer:             tlsObs.Issuer,
			Subject:            tlsObs.Subject,
			SANs:               tlsObs.SANs,
			ValidFrom:          tlsObs.ValidFrom,
			ValidTo:            tlsObs.ValidTo,
			VerificationResult: tlsObs.VerificationResult,
			VerificationReason: tlsObs.VerificationReason,
			NegotiatedVersion:  tlsObs.NegotiatedVersion,
			InsecureOverride:   tlsObs.InsecureOverride,
		}
		rec, err := evidence.NewTLSRecord(tlsInput)
		if err != nil {
			return nil, fmt.Errorf("build TLS evidence record: %w", err)
		}
		records = append(records, rec)
	}

	for i, red := range redirects {
		redObs := obs
		redObs.EvidenceID = fmt.Sprintf("%s-redirect-%d", obs.EvidenceID, i)
		redInput := evidence.RedirectRecordInput{
			Observation: redObs,
			FromURL:     red.FromURL,
			ToURL:       red.ToURL,
			StatusCode:  red.StatusCode,
			Authorized:  red.Authorized,
			Reason:      red.Reason,
		}
		rec, err := evidence.NewRedirectRecord(redInput)
		if err != nil {
			return nil, fmt.Errorf("build Redirect evidence record: %w", err)
		}
		records = append(records, rec)
	}

	if corrEv != nil {
		corrObs := obs
		corrObs.EvidenceID = fmt.Sprintf("%s-correlation", obs.EvidenceID)
		rec, err := evidence.NewCorrelationRecord(*corrEv, corrObs)
		if err != nil {
			return nil, fmt.Errorf("build Correlation evidence record: %w", err)
		}
		records = append(records, rec)
	}

	return records, nil
}

type mcpResourceReadResult struct {
	outcome        graph.Outcome
	reason         string
	details        map[string]any
	summary        *graph.ContentSummary
	truncated      bool
	truncateReason string
	degraded       bool
	degradeReason  string
}

func (c *Collector) readMCPResources(
	ctx context.Context,
	session *mcpsdk.ClientSession,
	srvID graph.Identity,
	scope, scanID, vantageKey, canonicalURL string,
	obsTime time.Time,
	resources []*mcpsdk.Resource,
) (mcpResourceReadResult, error) {
	budget := content.NewBudget(c.config.Content, secrets.NewRedactor(c.config.Secrets))
	var attempted, itemsRead, skippedBinary int
	var firstReadErr error
	var readErrors []string
	maxReadAttempts := c.config.Bounds.MaxItems
	if maxReadAttempts <= 0 {
		maxReadAttempts = 10000
	}

	for _, res := range resources {
		if res == nil || !isValidResourceKey(res.URI) {
			continue
		}
		if content.IsBinaryContent(res.URI, res.MIMEType) {
			skippedBinary++
			continue
		}
		if attempted >= maxReadAttempts {
			budget.MarkTruncated(fmt.Sprintf("MCP resource reads reached max_items (%d)", maxReadAttempts))
			break
		}
		attempted++
		callCtx, cancel := callTimeout(ctx, c.config.Bounds.ResponseTimeout)
		readRes, err := session.ReadResource(callCtx, &mcpsdk.ReadResourceParams{URI: res.URI})
		cancel()
		if err != nil {
			outcome, reason := classifyRPCError(err, OpResourcesRead)
			if firstReadErr == nil {
				firstReadErr = err
			}
			readErrors = append(readErrors, fmt.Sprintf("%s: %s", res.URI, reason))
			if outcome == graph.OutcomeUnsupported {
				break
			}
			continue
		}
		if readRes == nil {
			continue
		}

		resID := ""
		if rID, idErr := graph.NewResourceIdentity(scope, graph.MCPResource, srvID, res.URI); idErr == nil {
			resID = rID.ID()
		}
		for _, item := range readRes.Contents {
			if item == nil || len(item.Blob) > 0 || item.Text == "" {
				if item != nil && len(item.Blob) > 0 {
					skippedBinary++
				}
				continue
			}
			mimeType := item.MIMEType
			if mimeType == "" {
				mimeType = res.MIMEType
			}
			loc := item.URI
			if loc == "" {
				loc = res.URI
			}
			if content.IsBinaryContent(loc, mimeType) || content.LooksBinary([]byte(item.Text)) {
				skippedBinary++
				continue
			}
			if ok, _ := budget.ClaimResourceItem(res.URI); !ok {
				break
			}
			rec, added, addErr := budget.Add(content.RecordInput{
				DeploymentScope: scope,
				ScanID:          scanID,
				VantageKey:      vantageKey,
				ServiceID:       srvID.ID(),
				ResourceID:      resID,
				Surface:         "mcp",
				CheckID:         CheckIDResourcesRead,
				Source:          canonicalURL,
				Kind:            content.KindMCPResource,
				Location:        loc,
				MediaType:       mimeType,
				ObservedAt:      obsTime,
				Body:            item.Text,
			})
			if addErr != nil {
				return mcpResourceReadResult{}, fmt.Errorf("create mcp content record: %w", addErr)
			}
			if added {
				itemsRead++
				if c.contentSink != nil {
					if err := c.contentSink.Write(rec); err != nil {
						return mcpResourceReadResult{}, fmt.Errorf("write mcp content record: %w", err)
					}
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
	reason := fmt.Sprintf("read %d resource content item(s) (%d bytes)", itemsRead, budget.Bytes())
	if itemsRead == 0 {
		switch {
		case firstReadErr != nil:
			outcome, reason = classifyRPCError(firstReadErr, OpResourcesRead)
		case skippedBinary > 0:
			reason = fmt.Sprintf("skipped %d binary resource item(s)", skippedBinary)
		default:
			reason = "resources returned no text content"
		}
	}

	var summary *graph.ContentSummary
	if attempted > 0 || len(budget.Records()) > 0 || budget.Truncated() {
		summary = &graph.ContentSummary{
			Collected:         true,
			Bytes:             budget.Bytes(),
			Truncated:         budget.Truncated(),
			SecretTypes:       budget.SecretTypes(),
			SecretConfirmedAt: obsTime,
		}
	}

	degraded := itemsRead > 0 && len(readErrors) > 0
	degradeReason := ""
	if degraded {
		degradeReason = strings.Join(readErrors, "; ")
		outcome = graph.OutcomeFailed
		reason = fmt.Sprintf("read %d resource content item(s) but %d read(s) failed", itemsRead, len(readErrors))
	}
	return mcpResourceReadResult{
		outcome:        outcome,
		reason:         reason,
		details:        details,
		summary:        summary,
		truncated:      budget.Truncated(),
		truncateReason: strings.Join(budget.Reasons(), "; "),
		degraded:       degraded,
		degradeReason:  degradeReason,
	}, nil

}
