package mcp

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/0x3df/LLMHound/internal/checkpoint"
	"github.com/0x3df/LLMHound/internal/config"
	"github.com/0x3df/LLMHound/internal/correlate"
	"github.com/0x3df/LLMHound/internal/emitter"
	"github.com/0x3df/LLMHound/internal/evidence"
	"github.com/0x3df/LLMHound/internal/graph"
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

// WithCorrelator provides Computer correlation resolver and candidate inventory.
func WithCorrelator(resolver *correlate.Resolver, computers []correlate.Computer) Option {
	return func(c *Collector) {
		c.correlator = resolver
		c.computers = append([]correlate.Computer(nil), computers...)
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
	}
}

// WithCollectorVersion sets the reported collector version.
func WithCollectorVersion(version string) Option {
	return func(c *Collector) {
		c.collectorVersion = version
	}
}

// Collector performs anonymous, read-only collection of MCP metadata.
type Collector struct {
	config           config.Config
	customHTTPClient *http.Client
	correlator       *correlate.Resolver
	computers        []correlate.Computer
	clock            func() time.Time
	scanID           string
	evidenceID       string
	collectorVersion string
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
	vantageID, err := c.config.VantageIdentity()
	if err != nil {
		return nil, fmt.Errorf("vantage identity: %w", err)
	}

	return c.collectInternal(ctx, target, vantageID, c.config.Scope, c.scanID, c.evidenceID, c.collectorVersion)
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

	vantageID, err := graph.NewVantageIdentity(scope, vantageKey)
	if err != nil {
		return nil, fmt.Errorf("vantage identity: %w", err)
	}

	origTarget := target.OriginalTarget
	if origTarget == "" {
		origTarget = target.URL
	}

	if j != nil {
		_ = j.RecordTarget(checkpoint.TargetRecord{
			Target:  origTarget,
			Surface: "mcp",
			Status:  checkpoint.TargetStatusStarted,
		})
	}

	res, err := c.collectInternal(ctx, target, vantageID, scope, scanID, c.evidenceID, collectorVersion)
	if err != nil {
		if j != nil {
			_ = j.RecordTarget(checkpoint.TargetRecord{
				Target:  origTarget,
				Surface: "mcp",
				Status:  checkpoint.TargetStatusFailed,
				Error:   err.Error(),
			})
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
			VantageKey:       res.Observation.Vantage.ID(),
			Coverage:         string(res.Observation.Coverage),
			CoverageReason:   res.Observation.CoverageReason,
		}

		_ = j.RecordTarget(checkpoint.TargetRecord{
			Target:      origTarget,
			Surface:     "mcp",
			Status:      res.Status,
			Observation: &obsRec,
			Error:       res.Error,
		})
	}

	return res, nil
}

func (c *Collector) collectInternal(
	ctx context.Context,
	target Target,
	vantageID graph.Identity,
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
		c.config.Bounds.ConnectTimeout,
		c.config.Bounds.ResponseTimeout,
		c.config.Bounds.MaxRedirects,
		tracker,
	)

	srvID, err := graph.NewServiceIdentity(scope, graph.MCPServer, ep)
	if err != nil {
		return nil, fmt.Errorf("create MCPServer identity: %w", err)
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
			Vantage:          vantageID,
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
		addCheck(CheckIDPromptsList, OpPromptsList, "prerequisite failed: TLS verification failed", graph.OutcomeSkipped, nil, obs)
		addCheck(CheckIDRFC9728, OpRFC9728, "prerequisite failed: TLS verification failed", graph.OutcomeSkipped, nil, obs)

		evRecords = append(evRecords, c.buildEvidenceRecords(checks, checkDetails, nil, tlsObs, tracker.Redirects(), nil, obs)...)

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
		authServers, resource, rfcCode, rfcErr := executeRFC9728(ctx, httpClient, canonicalURL, c.config.Bounds.MaxResponseBytes)
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
		addCheck(CheckIDPromptsList, OpPromptsList, "prerequisite failed: server requires authentication", graph.OutcomeSkipped, nil, obs)

		evRecords = append(evRecords, c.buildEvidenceRecords(checks, checkDetails, nil, tlsObs, tracker.Redirects(), nil, obs)...)

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
		addCheck(CheckIDPromptsList, OpPromptsList, "prerequisite failed: access forbidden", graph.OutcomeSkipped, nil, obs)
		addCheck(CheckIDRFC9728, OpRFC9728, "not applicable; endpoint returned 403 not 401", graph.OutcomeSkipped, nil, obs)

		evRecords = append(evRecords, c.buildEvidenceRecords(checks, checkDetails, nil, tlsObs, tracker.Redirects(), nil, obs)...)

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
		addCheck(CheckIDPromptsList, OpPromptsList, "prerequisite failed: endpoint unreachable", graph.OutcomeSkipped, nil, obs)
		addCheck(CheckIDRFC9728, OpRFC9728, "not applicable; endpoint connection failed", graph.OutcomeSkipped, nil, obs)

		evRecords = append(evRecords, c.buildEvidenceRecords(checks, checkDetails, nil, tlsObs, tracker.Redirects(), nil, obs)...)

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
		tools, toolsTruncated, toolsTruncReason, toolsErr = executeToolsList(ctx, session, c.config.Bounds.MaxPages, c.config.Bounds.MaxItems)
	}

	// Enumerate resources (descriptors only, never content!)
	var resources []*mcpsdk.Resource
	var templates []*mcpsdk.ResourceTemplate
	var resTruncated bool
	var resTruncReason string
	var resErr error

	if initResult.Capabilities == nil || initResult.Capabilities.Resources == nil {
		// Capability not advertised
	} else {
		resources, templates, resTruncated, resTruncReason, resErr = executeResourcesList(ctx, session, c.config.Bounds.MaxPages, c.config.Bounds.MaxItems)
	}

	// Enumerate prompts
	var prompts []*mcpsdk.Prompt
	var promptsTruncated bool
	var promptsTruncReason string
	var promptsErr error

	if initResult.Capabilities == nil || initResult.Capabilities.Prompts == nil {
		// Capability not advertised
	} else {
		prompts, promptsTruncated, promptsTruncReason, promptsErr = executePromptsList(ctx, session, c.config.Bounds.MaxPages, c.config.Bounds.MaxItems)
	}

	// Determine surface coverage
	var finalCoverage graph.Coverage
	var finalCoverageReason string

	if toolsTruncated || resTruncated || promptsTruncated {
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
		finalCoverageReason = strings.Join(reasons, "; ")
	} else if toolsErr != nil || resErr != nil || promptsErr != nil {
		finalCoverage = graph.CoveragePartial
		var reasons []string
		if toolsErr != nil {
			reasons = append(reasons, "tools/list: "+toolsErr.Error())
		}
		if resErr != nil {
			reasons = append(reasons, "resources/list: "+resErr.Error())
		}
		if promptsErr != nil {
			reasons = append(reasons, "prompts/list: "+promptsErr.Error())
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
		addCheck(CheckIDResourcesList, OpResourcesList, "resources enumerated successfully", graph.OutcomeSuccess, details, finalObs)
	}

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

	// 1. Server node
	srvNode, err := buildServerNode(srvID, ep, finalObs, initResult, tlsObs)
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

	// 5. UnauthenticatedAccess edge
	accessEdge, err := buildAccessEdge(vantageID, srvID, finalObs, CheckIDInitialize, OpInitialize, initSuccessReason)
	if err != nil {
		return nil, fmt.Errorf("build UnauthenticatedAccess edge: %w", err)
	}
	edges = append(edges, accessEdge)

	// 6. Computer correlation and ObservedAt edge
	observedAtEdge, fallbackNode, corrEv, err := buildCorrelationEdgeAndFallback(
		scope,
		origTarget,
		srvID,
		finalObs,
		c.correlator,
		c.computers,
	)
	if err != nil {
		return nil, fmt.Errorf("build correlation edge: %w", err)
	}
	edges = append(edges, observedAtEdge)
	if fallbackNode != nil {
		nodes = append(nodes, *fallbackNode)
	}

	// 7. Fingerprint input
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

	evRecords = append(evRecords, c.buildEvidenceRecords(checks, checkDetails, fpInput, tlsObs, tracker.Redirects(), &corrEv, finalObs)...)

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
	checks []graph.CheckResult,
	checkDetails map[string]map[string]any,
	fpInput *evidence.FingerprintInput,
	tlsObs *tlsObservation,
	redirects []redirectInfo,
	corrEv *correlate.Evidence,
	obs graph.Observation,
) []evidence.Record {
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
			if rec, err := evidence.NewAccessEvidenceRecord(accEv, details); err == nil {
				records = append(records, rec)
			}
		} else {
			if rec, err := evidence.NewCheckResultRecord(check, details); err == nil {
				records = append(records, rec)
			}
		}
	}

	if fpInput != nil {
		fpObs := obs
		fpObs.EvidenceID = fmt.Sprintf("%s-fingerprint", obs.EvidenceID)
		fpInput.Observation = fpObs
		if rec, err := evidence.NewFingerprintRecord(*fpInput); err == nil {
			records = append(records, rec)
		}
	}

	if tlsObs != nil {
		tlsObsRecord := obs
		tlsObsRecord.EvidenceID = fmt.Sprintf("%s-tls", obs.EvidenceID)
		tlsInput := evidence.TLSRecordInput{
			Observation:        tlsObsRecord,
			TargetID:           obs.Source,
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
		if rec, err := evidence.NewTLSRecord(tlsInput); err == nil {
			records = append(records, rec)
		}
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
		if rec, err := evidence.NewRedirectRecord(redInput); err == nil {
			records = append(records, rec)
		}
	}

	if corrEv != nil {
		corrObs := obs
		corrObs.EvidenceID = fmt.Sprintf("%s-correlation", obs.EvidenceID)
		if rec, err := evidence.NewCorrelationRecord(*corrEv, corrObs); err == nil {
			records = append(records, rec)
		}
	}

	return records
}
