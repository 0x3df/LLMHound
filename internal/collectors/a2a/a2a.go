// Package a2a provides anonymous, read-only enumeration of Agent2Agent (A2A)
// endpoints via their public agent card metadata without invoking skills or
// following linked URLs.
package a2a

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
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
	// Surface is the canonical surface identifier for A2A agents.
	Surface = "a2a"

	// DefaultPort is the default listener port probed for A2A endpoints.
	DefaultPort = 8080

	// CheckAgentCard is the allowlisted check identifier for public agent cards.
	CheckAgentCard = "a2a_agent_card"

	primaryCardPath = "/.well-known/agent-card.json"
	legacyCardPath  = "/.well-known/agent.json"
)

// AgentProvider describes the organization operating an A2A agent.
type AgentProvider struct {
	Organization string `json:"organization,omitempty"`
	URL          string `json:"url,omitempty"`
}

// AgentCapabilities lists optional A2A protocol features advertised by the agent.
type AgentCapabilities struct {
	Streaming              *bool `json:"streaming,omitempty"`
	PushNotifications      *bool `json:"pushNotifications,omitempty"`
	StateTransitionHistory *bool `json:"stateTransitionHistory,omitempty"`
	ExtendedAgentCard      *bool `json:"extendedAgentCard,omitempty"`
}

// SecurityScheme describes a declared authentication scheme in an agent card.
type SecurityScheme struct {
	Type         string `json:"type,omitempty"`
	Scheme       string `json:"scheme,omitempty"`
	Name         string `json:"name,omitempty"`
	In           string `json:"in,omitempty"`
	BearerFormat string `json:"bearerFormat,omitempty"`
}

// AgentInterface describes an advertised transport endpoint for the agent.
type AgentInterface struct {
	URL             string `json:"url,omitempty"`
	Transport       string `json:"transport,omitempty"`
	ProtocolBinding string `json:"protocolBinding,omitempty"`
}

// AgentSkill describes an advertised skill on an A2A agent card.
type AgentSkill struct {
	ID          string   `json:"id,omitempty"`
	Name        string   `json:"name,omitempty"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	InputModes  []string `json:"inputModes,omitempty"`
	OutputModes []string `json:"outputModes,omitempty"`
}

// AgentCard models the A2A public agent card metadata.
type AgentCard struct {
	Name                 string                    `json:"name"`
	Description          string                    `json:"description,omitempty"`
	URL                  string                    `json:"url,omitempty"`
	Version              string                    `json:"version,omitempty"`
	ProtocolVersion      string                    `json:"protocolVersion,omitempty"`
	DocumentationURL     string                    `json:"documentationUrl,omitempty"`
	Provider             *AgentProvider            `json:"provider,omitempty"`
	Capabilities         *AgentCapabilities        `json:"capabilities,omitempty"`
	SecuritySchemes      map[string]SecurityScheme `json:"securitySchemes,omitempty"`
	Security             []map[string][]string     `json:"security,omitempty"`
	DefaultInputModes    []string                  `json:"defaultInputModes,omitempty"`
	DefaultOutputModes   []string                  `json:"defaultOutputModes,omitempty"`
	Skills               []AgentSkill              `json:"skills,omitempty"`
	AdditionalInterfaces []AgentInterface          `json:"additionalInterfaces,omitempty"`
	SupportedInterfaces  []AgentInterface          `json:"supportedInterfaces,omitempty"`
}

// Collector implements anonymous, read-only A2A agent-card enumeration.
type Collector struct {
	cfg         config.Config
	transport   *transport.Client
	contentSink content.Sink
}

// Option configures an A2A Collector.
type Option func(*Collector)

// WithTransport overrides the transport client (primarily for testing).
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

// New constructs an A2A collector with the given configuration.
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

// Collect fetches the public A2A agent card without invoking skills or following
// external links, emitting A2AAgent, A2ASkill, and attachment artifacts.
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

	srvID, err := graph.NewServiceIdentity(scope, graph.A2AAgent, ep)
	if err != nil {
		return checkpoint.Result{}, fmt.Errorf("create service identity: %w", err)
	}

	evID := common.EvidenceID(scanID, srvID.ID(), obsTime)
	baseURL := strings.TrimSuffix(ep.String(), "/")
	cardPath := primaryCardPath

	var tlsInfo *transport.TLSInfo
	var redirects []transport.RedirectInfo

	resp, reqErr := c.transport.Get(ctx, baseURL+cardPath)
	common.AbsorbTransport(resp, &tlsInfo, &redirects)

	if common.IsTLSFailure(tlsInfo, c.cfg.Insecure) {
		return c.tlsFailedResult(target, scope, vantageKey, scanID, obsTime, evID, baseURL+cardPath, srvID, reqErr, tlsInfo, redirects)
	}

	if reqErr == nil && resp.StatusCode == http.StatusNotFound {
		cardPath = legacyCardPath
		resp, reqErr = c.transport.Get(ctx, baseURL+cardPath)
		common.AbsorbTransport(resp, &tlsInfo, &redirects)
		if common.IsTLSFailure(tlsInfo, c.cfg.Insecure) {
			return c.tlsFailedResult(target, scope, vantageKey, scanID, obsTime, evID, baseURL+cardPath, srvID, reqErr, tlsInfo, redirects)
		}
	}

	sourceURL := baseURL + cardPath
	var checks []common.CheckEntry
	var card AgentCard
	var cardOK bool
	var cardTruncated bool
	var finalCoverage graph.Coverage
	var finalCoverageReason string
	var finalStatus checkpoint.TargetStatus
	var fpInput *evidence.FingerprintInput

	if reqErr != nil {
		reason := common.SanitizeError(reqErr)
		checks = append(checks, common.CheckEntry{
			CheckID:       CheckAgentCard,
			Operation:     CheckAgentCard,
			Outcome:       graph.OutcomeFailed,
			Reason:        reason,
			OperationKind: graph.EnumerationOperation,
			Details:       map[string]any{"card_path": cardPath, "error": reason},
		})
		finalCoverage = graph.CoverageFailed
		finalCoverageReason = "target unreachable: " + reason
		finalStatus = checkpoint.TargetStatusFailed
	} else {
		switch resp.StatusCode {
		case http.StatusOK:
			if resp.Truncated {
				reason := "agent card response truncated at max_response_bytes limit"
				checks = append(checks, common.CheckEntry{
					CheckID:       CheckAgentCard,
					Operation:     CheckAgentCard,
					Outcome:       graph.OutcomeFailed,
					Reason:        reason,
					OperationKind: graph.EnumerationOperation,
					Details:       map[string]any{"http_status": resp.StatusCode, "card_path": cardPath, "truncated": true},
				})
				finalCoverage = graph.CoverageFailed
				finalCoverageReason = reason
				finalStatus = checkpoint.TargetStatusFailed
			} else if err := json.Unmarshal(resp.Body, &card); err != nil || !isValidAgentCard(card) {
				reason := "malformed or non-A2A agent card JSON"
				checks = append(checks, common.CheckEntry{
					CheckID:       CheckAgentCard,
					Operation:     CheckAgentCard,
					Outcome:       graph.OutcomeFailed,
					Reason:        reason,
					OperationKind: graph.EnumerationOperation,
					Details:       map[string]any{"http_status": resp.StatusCode, "card_path": cardPath},
				})
				finalCoverage = graph.CoverageFailed
				finalCoverageReason = reason
				finalStatus = checkpoint.TargetStatusFailed
			} else {
				cardOK = true
				finalCoverage = graph.CoverageComplete
				finalStatus = checkpoint.TargetStatusCompleted
			}
		case http.StatusUnauthorized, http.StatusForbidden:
			reason := fmt.Sprintf("HTTP %d: authentication or authorization required for agent card", resp.StatusCode)
			checks = append(checks, common.CheckEntry{
				CheckID:       CheckAgentCard,
				Operation:     CheckAgentCard,
				Outcome:       graph.OutcomeDenied,
				Reason:        reason,
				OperationKind: graph.EnumerationOperation,
				Details:       map[string]any{"http_status": resp.StatusCode, "card_path": cardPath},
			})
			finalCoverage = graph.CoveragePartial
			finalCoverageReason = reason
			finalStatus = checkpoint.TargetStatusPartial
		case http.StatusNotFound:
			reason := fmt.Sprintf("HTTP 404 not found on %s and %s", primaryCardPath, legacyCardPath)
			checks = append(checks, common.CheckEntry{
				CheckID:       CheckAgentCard,
				Operation:     CheckAgentCard,
				Outcome:       graph.OutcomeFailed,
				Reason:        reason,
				OperationKind: graph.EnumerationOperation,
				Details:       map[string]any{"http_status": resp.StatusCode, "card_path": cardPath},
			})
			finalCoverage = graph.CoverageFailed
			finalCoverageReason = reason
			finalStatus = checkpoint.TargetStatusFailed
		case http.StatusTooManyRequests:
			reason := "HTTP 429 rate limited"
			checks = append(checks, common.CheckEntry{
				CheckID:       CheckAgentCard,
				Operation:     CheckAgentCard,
				Outcome:       graph.OutcomeFailed,
				Reason:        reason,
				OperationKind: graph.EnumerationOperation,
				Details:       map[string]any{"http_status": resp.StatusCode, "card_path": cardPath},
			})
			finalCoverage = graph.CoverageFailed
			finalCoverageReason = reason
			finalStatus = checkpoint.TargetStatusFailed
		default:
			reason := fmt.Sprintf("HTTP %d unexpected status", resp.StatusCode)
			checks = append(checks, common.CheckEntry{
				CheckID:       CheckAgentCard,
				Operation:     CheckAgentCard,
				Outcome:       graph.OutcomeFailed,
				Reason:        reason,
				OperationKind: graph.EnumerationOperation,
				Details:       map[string]any{"http_status": resp.StatusCode, "card_path": cardPath},
			})
			finalCoverage = graph.CoverageFailed
			finalCoverageReason = reason
			finalStatus = checkpoint.TargetStatusFailed
		}
	}

	var skills []AgentSkill
	var skillsTruncated bool
	var contentSummary *graph.ContentSummary

	if cardOK {
		deduped := dedupeSkills(card.Skills)
		maxItems := c.cfg.Bounds.MaxItems
		if maxItems <= 0 {
			maxItems = 10000
		}
		if len(deduped) > maxItems {
			skillsTruncated = true
			skills = deduped[:maxItems]
		} else {
			skills = deduped
		}

		checkDetails := map[string]any{
			"http_status": http.StatusOK,
			"card_path":   cardPath,
			"skill_count": len(skills),
			"truncated":   skillsTruncated,
		}

		if c.cfg.Content.EnabledFor(Surface) {
			budget := content.NewBudget(c.cfg.Content, secrets.NewRedactor(c.cfg.Secrets))
			if ok, _ := budget.ClaimResourceItem(cardPath); ok {
				rec, added, addErr := budget.Add(content.RecordInput{
					DeploymentScope: scope,
					ScanID:          scanID,
					VantageKey:      vantageKey,
					ServiceID:       srvID.ID(),
					Surface:         Surface,
					CheckID:         CheckAgentCard,
					Source:          sourceURL,
					Kind:            content.KindConfig,
					Location:        cardPath,
					MediaType:       "application/json",
					ObservedAt:      obsTime,
					Body:            string(resp.Body),
				})
				if addErr != nil {
					return checkpoint.Result{}, fmt.Errorf("create a2a content record: %w", addErr)
				}
				if added && c.contentSink != nil {
					if err := c.contentSink.Write(rec); err != nil {
						return checkpoint.Result{}, fmt.Errorf("write a2a content record: %w", err)
					}
				}
				cfgBool := added
				contentSummary = common.ContentSummaryFromBudget(budget, obsTime, nil, &cfgBool)
				cardTruncated = budget.Truncated()
				checkDetails["content_bytes"] = budget.Bytes()
				checkDetails["content_truncated"] = cardTruncated
				if found := budget.Findings(); len(found) > 0 {
					checkDetails["detected_exposures"] = content.ExposureDetails(found)
				}
			}
		}

		checks = append(checks, common.CheckEntry{
			CheckID:        CheckAgentCard,
			Operation:      CheckAgentCard,
			Outcome:        graph.OutcomeSuccess,
			Reason:         "agent card retrieved anonymously via " + cardPath,
			Anonymous:      true,
			OperationKind:  graph.EnumerationOperation,
			CountForAccess: true,
			Details:        checkDetails,
		})

		if skillsTruncated || cardTruncated {
			var reasons []string
			if skillsTruncated {
				reasons = append(reasons, fmt.Sprintf("agent skills truncated at max_items (%d)", maxItems))
			}
			if cardTruncated {
				reasons = append(reasons, "agent card content truncated at configured bounds")
			}
			finalCoverage = graph.CoverageTruncated
			finalCoverageReason = strings.Join(reasons, "; ")
			finalStatus = checkpoint.TargetStatusPartial
		}

		vendor := ""
		if card.Provider != nil {
			vendor = redactWithConfig(c.cfg.Secrets, common.BoundString(card.Provider.Organization, 200))
		}
		rawVer := common.BoundString(card.Version, 128)
		normVer := common.NormalizeVersion(card.Version)
		protoVer := common.BoundString(card.ProtocolVersion, 128)
		fpInput = &evidence.FingerprintInput{
			TargetID:           srvID.ID(),
			Product:            "A2A Agent",
			Vendor:             vendor,
			SoftwareVersion:    normVer,
			SoftwareVersionRaw: rawVer,
			ProtocolVersion:    protoVer,
			Method:             CheckAgentCard,
			Confidence:         "observed",
			Details: map[string]any{
				"card_path":   cardPath,
				"http_status": http.StatusOK,
			},
		}
	}

	obs := graph.Observation{
		SchemaVersion:    "1",
		ScanID:           scanID,
		CollectorVersion: collectorVersion(c.cfg),
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
	var corrRec *evidence.Record

	if finalCoverage != graph.CoverageFailed {
		redactor := secrets.NewRedactor(c.cfg.Secrets)
		redactText := func(s string, maxLen int) string {
			bounded := common.BoundString(s, maxLen)
			if bounded != "" && redactor != nil {
				bounded, _ = redactor(bounded)
			}
			return bounded
		}

		access := common.SummarizeAccess(srvID.ID(), obs, checks)
		facts := graph.ServiceFacts{
			Endpoint:   ep,
			Name:       fmt.Sprintf("A2A · %s:%d", ep.Host(), ep.Port()),
			Product:    "A2A Agent",
			VantageKey: vantageKey,
			Access:     access,
			TLS:        common.TLSSummary(tlsInfo),
			Content:    contentSummary,
		}
		if cardOK {
			if card.Provider != nil {
				facts.Vendor = redactText(card.Provider.Organization, 200)
			}
			facts.AuthAdvertised = deriveAuthAdvertised(card)
			if hasDeclaredExecSurface(card) {
				facts.ExecSurface = []string{graph.ExecToolInvocation}
				facts.ExecSurfaceBasis = graph.BasisDeclared
			}
			if refs := collectBackendRefs(card); len(refs) > 0 {
				facts.BackendRefs = refs
				facts.BackendRefsBasis = graph.BasisDeclared
			}
			facts.SkillCount = common.IntPtr(len(skills))
		}

		srvProps := facts.Properties()
		srvProps["card_path"] = cardPath
		if cardOK {
			if name := redactText(card.Name, 512); name != "" {
				srvProps["agent_name"] = name
			}
			if desc := redactText(card.Description, 2048); desc != "" {
				srvProps["description"] = desc
			}
			if rawVer := common.BoundString(card.Version, 128); rawVer != "" {
				srvProps["software_version_raw"] = rawVer
				if norm := common.NormalizeVersion(card.Version); norm != "" {
					srvProps["software_version"] = norm
				}
			}
			if proto := common.BoundString(card.ProtocolVersion, 128); proto != "" {
				srvProps["protocol_version"] = proto
			}
			if caps := extractCapabilities(card.Capabilities); len(caps) > 0 {
				srvProps["capabilities"] = caps
			}
			if schemes := extractSecuritySchemes(card.SecuritySchemes); len(schemes) > 0 {
				srvProps["security_schemes"] = schemes
			}
			if inModes := cleanStringSlice(card.DefaultInputModes, 128); len(inModes) > 0 {
				srvProps["default_input_modes"] = inModes
			}
			if outModes := cleanStringSlice(card.DefaultOutputModes, 128); len(outModes) > 0 {
				srvProps["default_output_modes"] = outModes
			}
			if card.Provider != nil {
				if pURL := common.SanitizeHTTPReference(card.Provider.URL); pURL != "" {
					srvProps["provider_url"] = pURL
				}
			}
			if docURL := common.SanitizeHTTPReference(card.DocumentationURL); docURL != "" {
				srvProps["documentation_url"] = docURL
			}
		}

		srvNode, err := graph.NewNode(srvID, obs)
		if err != nil {
			return checkpoint.Result{}, fmt.Errorf("create A2AAgent node: %w", err)
		}
		srvItem, err := emitter.NewNodeItem(srvNode, srvProps)
		if err != nil {
			return checkpoint.Result{}, fmt.Errorf("create A2AAgent node item: %w", err)
		}
		nodes = append(nodes, srvItem)

		for _, sk := range skills {
			key := skillKey(sk)
			skillID, err := graph.NewResourceIdentity(scope, graph.A2ASkill, srvID, key)
			if err != nil {
				continue
			}
			skillNode, err := graph.NewNode(skillID, obs)
			if err != nil {
				continue
			}
			display := redactText(sk.Name, 256)
			if display == "" {
				display = redactText(key, 256)
			}
			skProps := map[string]any{
				"name":         strings.ToUpper(display),
				"display_name": display,
				"skill_id":     redactText(key, 256),
			}
			if skName := redactText(sk.Name, 256); skName != "" {
				skProps["skill_name"] = skName
			}
			if desc := redactText(sk.Description, 2048); desc != "" {
				skProps["description"] = desc
			}
			if tags := cleanStringSlice(sk.Tags, 128); len(tags) > 0 {
				skProps["tags"] = tags
			}
			if inModes := cleanStringSlice(sk.InputModes, 128); len(inModes) > 0 {
				skProps["input_modes"] = inModes
			}
			if outModes := cleanStringSlice(sk.OutputModes, 128); len(outModes) > 0 {
				skProps["output_modes"] = outModes
			}

			skItem, err := emitter.NewNodeItem(skillNode, skProps)
			if err != nil {
				continue
			}
			edge, err := graph.NewTopologyEdge(graph.AdvertisesSkill, srvID.Reference(), skillID.Reference(), obs)
			if err != nil {
				continue
			}
			nodes = append(nodes, skItem)
			edges = append(edges, edge)
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
		Details: map[string]any{
			"endpoint":  ep.String(),
			"card_path": cardPath,
		},
	}
	if err := res.Validate(scope); err != nil {
		return checkpoint.Result{}, fmt.Errorf("validate result: %w", err)
	}
	return res, nil
}

func (c *Collector) tlsFailedResult(
	target, scope, vantageKey, scanID string,
	obsTime time.Time,
	evID, sourceURL string,
	srvID graph.Identity,
	reqErr error,
	tlsInfo *transport.TLSInfo,
	redirects []transport.RedirectInfo,
) (checkpoint.Result, error) {
	reason := common.SanitizeError(reqErr)
	if reason == "" && tlsInfo != nil && tlsInfo.VerificationReason != "" {
		reason = "TLS certificate verification failed: " + common.BoundString(tlsInfo.VerificationReason, 200)
	}
	if reason == "" {
		reason = "TLS certificate verification failed"
	}
	obs := graph.Observation{
		SchemaVersion:    "1",
		ScanID:           scanID,
		CollectorVersion: collectorVersion(c.cfg),
		EvidenceID:       evID,
		Source:           sourceURL,
		Surface:          Surface,
		ObservedAt:       obsTime,
		DeploymentScope:  scope,
		VantageKey:       vantageKey,
		Coverage:         graph.CoverageFailed,
		CoverageReason:   reason,
	}
	checks := []common.CheckEntry{{
		CheckID:       CheckAgentCard,
		Operation:     CheckAgentCard,
		Outcome:       graph.OutcomeFailed,
		Reason:        reason,
		OperationKind: graph.EnumerationOperation,
		Details:       map[string]any{"tls_error": common.BoundString(tlsInfo.VerificationReason, 200)},
	}}
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

func collectorVersion(cfg config.Config) string {
	_ = cfg
	return "0.1.0"
}

func redactWithConfig(cfg config.Secrets, s string) string {
	if s == "" {
		return ""
	}
	if redactor := secrets.NewRedactor(cfg); redactor != nil {
		s, _ = redactor(s)
	}
	return s
}

func isValidAgentCard(card AgentCard) bool {
	if strings.TrimSpace(card.Name) == "" {
		return false
	}
	return card.Skills != nil ||
		card.Capabilities != nil ||
		strings.TrimSpace(card.URL) != "" ||
		strings.TrimSpace(card.ProtocolVersion) != "" ||
		len(card.DefaultInputModes) > 0 ||
		len(card.SupportedInterfaces) > 0 ||
		len(card.AdditionalInterfaces) > 0
}

func deriveAuthAdvertised(card AgentCard) string {
	hasNonEmptyReq := false
	hasEmptyReq := false
	for _, req := range card.Security {
		if len(req) == 0 {
			hasEmptyReq = true
		} else {
			hasNonEmptyReq = true
		}
	}
	if hasEmptyReq && (hasNonEmptyReq || len(card.SecuritySchemes) > 0) {
		return "mixed"
	}
	if len(card.SecuritySchemes) > 0 || hasNonEmptyReq {
		return "required"
	}
	if hasEmptyReq {
		return "none"
	}
	return ""
}

func hasDeclaredExecSurface(card AgentCard) bool {
	return len(card.Skills) > 0 ||
		strings.TrimSpace(card.URL) != "" ||
		len(card.AdditionalInterfaces) > 0 ||
		len(card.SupportedInterfaces) > 0
}

func collectBackendRefs(card AgentCard) []string {
	seen := make(map[string]bool)
	var out []string
	add := func(raw string) {
		san := common.SanitizeHTTPReference(raw)
		if san != "" && !seen[san] {
			seen[san] = true
			out = append(out, san)
		}
	}
	add(card.URL)
	for _, iface := range card.AdditionalInterfaces {
		add(iface.URL)
	}
	for _, iface := range card.SupportedInterfaces {
		add(iface.URL)
	}
	sort.Strings(out)
	return out
}

func extractCapabilities(caps *AgentCapabilities) []string {
	if caps == nil {
		return nil
	}
	var out []string
	if caps.Streaming != nil && *caps.Streaming {
		out = append(out, "streaming")
	}
	if caps.PushNotifications != nil && *caps.PushNotifications {
		out = append(out, "push_notifications")
	}
	if caps.StateTransitionHistory != nil && *caps.StateTransitionHistory {
		out = append(out, "state_transition_history")
	}
	if caps.ExtendedAgentCard != nil && *caps.ExtendedAgentCard {
		out = append(out, "extended_agent_card")
	}
	sort.Strings(out)
	return out
}

func extractSecuritySchemes(schemes map[string]SecurityScheme) []string {
	if len(schemes) == 0 {
		return nil
	}
	var out []string
	for k, v := range schemes {
		name := common.BoundString(k, 64)
		if name == "" {
			continue
		}
		typ := common.BoundString(v.Type, 64)
		if typ != "" {
			out = append(out, name+":"+typ)
		} else {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func cleanStringSlice(in []string, maxLen int) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	var out []string
	for _, s := range in {
		cleaned := common.BoundString(s, maxLen)
		if cleaned != "" && !seen[cleaned] {
			seen[cleaned] = true
			out = append(out, cleaned)
		}
	}
	return out
}

func skillKey(sk AgentSkill) string {
	if k := strings.TrimSpace(sk.ID); k != "" {
		return k
	}
	return strings.TrimSpace(sk.Name)
}

func dedupeSkills(in []AgentSkill) []AgentSkill {
	seen := make(map[string]bool, len(in))
	out := make([]AgentSkill, 0, len(in))
	for _, sk := range in {
		k := skillKey(sk)
		if k == "" || seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, sk)
	}
	return out
}
