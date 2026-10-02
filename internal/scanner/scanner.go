package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"github.com/0x3df/LLMHound/internal/checkpoint"
	"github.com/0x3df/LLMHound/internal/collectors/jupyter"
	collectormcp "github.com/0x3df/LLMHound/internal/collectors/mcp"
	"github.com/0x3df/LLMHound/internal/collectors/ollama"
	"github.com/0x3df/LLMHound/internal/config"
	"github.com/0x3df/LLMHound/internal/correlate"
	"github.com/0x3df/LLMHound/internal/discovery"
	"github.com/0x3df/LLMHound/internal/emitter"
	"github.com/0x3df/LLMHound/internal/graph"
)

// PlannedCheck describes an allowlisted check planned for a surface.
type PlannedCheck struct {
	CheckID    string `json:"check_id"`
	Operation  string `json:"operation"`
	Method     string `json:"method"`
	Endpoint   string `json:"endpoint"`
	Purpose    string `json:"purpose"`
	Active     bool   `json:"active"`
	SkipReason string `json:"skip_reason,omitempty"`
}

// SurfacePlan describes planned collection operations for a specific surface on a target.
type SurfacePlan struct {
	Surface discovery.Surface `json:"surface"`
	Port    int               `json:"port"`
	Checks  []PlannedCheck    `json:"checks"`
}

// TargetPlan describes all planned collection checks for a specific target host.
type TargetPlan struct {
	Target   string        `json:"target"`
	Surfaces []SurfacePlan `json:"surfaces"`
}

// ScanResult contains the metadata, paths, and replayed graph state from a scan run.
type ScanResult struct {
	ScanID       string
	Prefix       string
	OutputDir    string
	JournalPath  string
	Artifacts    emitter.ScanArtifacts
	TargetsCount int
	State        *checkpoint.State
}

// Option configures Scanner behavior.
type Option func(*Scanner)

// WithDefinitions sets custom discovery fingerprint definitions.
func WithDefinitions(defs []discovery.Definition) Option {
	return func(s *Scanner) {
		s.definitions = defs
	}
}

// WithVerifiedComputers provides pre-verified native Computer candidates for correlation.
func WithVerifiedComputers(computers []correlate.Computer) Option {
	return func(s *Scanner) {
		s.verifiedComputers = append([]correlate.Computer(nil), computers...)
	}
}

// WithResolver provides an explicit correlation resolver.
func WithResolver(r *correlate.Resolver) Option {
	return func(s *Scanner) {
		s.resolver = r
	}
}

// WithHTTPClient overrides the default HTTP client used for collection/probing.
func WithHTTPClient(client *http.Client) Option {
	return func(s *Scanner) {
		s.httpClient = client
	}
}

// WithNow sets the clock used for scan and observation timestamps.
func WithNow(now func() time.Time) Option {
	return func(s *Scanner) {
		s.now = now
	}
}

// WithCollectorVersion sets the collector version reported in headers and evidence.
func WithCollectorVersion(version string) Option {
	return func(s *Scanner) {
		s.collectorVersion = version
	}
}

// Scanner coordinates discovery, collectors, checkpointing, and emission for a scan.
type Scanner struct {
	cfg               config.Config
	definitions       []discovery.Definition
	verifiedComputers []correlate.Computer
	resolver          *correlate.Resolver
	httpClient        *http.Client
	now               func() time.Time
	collectorVersion  string
}

// New creates and initializes a Scanner instance.
func New(cfg config.Config, opts ...Option) (*Scanner, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	s := &Scanner{
		cfg:              cfg,
		definitions:      discovery.BuiltinDefinitions(),
		now:              func() time.Time { return time.Now().UTC() },
		collectorVersion: "0.1.0",
	}

	for _, opt := range opts {
		opt(s)
	}

	return s, nil
}

// Plan returns the static targets x checks plan without making any network connections.
func (s *Scanner) Plan(targets []string) []TargetPlan {
	var plans []TargetPlan
	for _, target := range targets {
		tp := TargetPlan{
			Target:   target,
			Surfaces: s.planSurfaces(target),
		}
		plans = append(plans, tp)
	}
	return plans
}

func (s *Scanner) planSurfaces(_ string) []SurfacePlan {
	var surfacePlans []SurfacePlan

	hasOptIn := s.cfg.OptIns.Prompts || s.cfg.OptIns.ConfigurationContent || s.cfg.OptIns.ResourceContent

	for _, def := range s.definitions {
		sp := SurfacePlan{
			Surface: def.Surface,
			Port:    def.DefaultPort,
		}

		switch def.Surface {
		case discovery.SurfaceJupyter:
			sp.Checks = []PlannedCheck{
				{
					CheckID:   jupyter.CheckIDVersion,
					Operation: "jupyter_api_version",
					Method:    http.MethodGet,
					Endpoint:  "/api",
					Purpose:   "Retrieve reported API version and server version metadata",
					Active:    true,
				},
				{
					CheckID:   jupyter.CheckIDSessions,
					Operation: "jupyter_sessions",
					Method:    http.MethodGet,
					Endpoint:  "/api/sessions",
					Purpose:   "Enumerate active session count, kernel names, and execution states",
					Active:    true,
				},
				{
					CheckID:   jupyter.CheckIDContents,
					Operation: "jupyter_contents_list",
					Method:    http.MethodGet,
					Endpoint:  "/api/contents",
					Purpose:   "Enumerate top-level workspace notebook and file metadata without bodies",
					Active:    true,
				},
			}

		case discovery.SurfaceMCP:
			sp.Checks = []PlannedCheck{
				{
					CheckID:   collectormcp.CheckIDInitialize,
					Operation: collectormcp.OpInitialize,
					Method:    http.MethodPost,
					Endpoint:  "/mcp",
					Purpose:   "Initialize protocol session and negotiate capabilities",
					Active:    true,
				},
				{
					CheckID:   collectormcp.CheckIDToolsList,
					Operation: collectormcp.OpToolsList,
					Method:    http.MethodPost,
					Endpoint:  "/mcp",
					Purpose:   "Enumerate available tools with input schemas and annotations",
					Active:    true,
				},
				{
					CheckID:   collectormcp.CheckIDResourcesList,
					Operation: collectormcp.OpResourcesList,
					Method:    http.MethodPost,
					Endpoint:  "/mcp",
					Purpose:   "Enumerate resource descriptors and URI templates without content",
					Active:    true,
				},
				{
					CheckID:   collectormcp.CheckIDPromptsList,
					Operation: collectormcp.OpPromptsList,
					Method:    http.MethodPost,
					Endpoint:  "/mcp",
					Purpose:   "Enumerate prompt templates and parameter descriptors",
					Active:    true,
				},
				{
					CheckID:   collectormcp.CheckIDRFC9728,
					Operation: collectormcp.OpRFC9728,
					Method:    http.MethodGet,
					Endpoint:  "/.well-known/oauth-protected-resource",
					Purpose:   "Discover OAuth authorization server metadata when 401 is encountered",
					Active:    true,
				},
			}

		case discovery.SurfaceOllama:
			showCheck := PlannedCheck{
				CheckID:   ollama.CheckShow,
				Operation: "ollama_show",
				Method:    http.MethodPost,
				Endpoint:  "/api/show",
				Purpose:   "Retrieve redacted model provenance (parent_model, license, family)",
				Active:    hasOptIn,
			}
			if !hasOptIn {
				showCheck.SkipReason = "policy: sensitive modelfile/prompt read requires explicit opt-in"
			}

			sp.Checks = []PlannedCheck{
				{
					CheckID:   ollama.CheckVersion,
					Operation: "ollama_version",
					Method:    http.MethodGet,
					Endpoint:  "/api/version",
					Purpose:   "Retrieve runtime software version",
					Active:    true,
				},
				{
					CheckID:   ollama.CheckTags,
					Operation: "ollama_tags",
					Method:    http.MethodGet,
					Endpoint:  "/api/tags",
					Purpose:   "Enumerate model catalog, digests, format, and quantization",
					Active:    true,
				},
				{
					CheckID:   ollama.CheckPS,
					Operation: "ollama_ps",
					Method:    http.MethodGet,
					Endpoint:  "/api/ps",
					Purpose:   "Enumerate models currently loaded in memory",
					Active:    true,
				},
				showCheck,
			}
		}

		surfacePlans = append(surfacePlans, sp)
	}

	return surfacePlans
}

// Scan executes target enumeration across supported collectors, writing through
// a checkpoint journal and emitting OpenGraph payload and evidence sidecars.
func (s *Scanner) Scan(ctx context.Context, targets []string, outputDir, prefix string) (*ScanResult, error) {
	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets to scan")
	}

	if outputDir == "" {
		outputDir = "."
	}

	now := s.now().UTC()
	scanID := "scan-" + now.Format("20060102150405")
	if prefix == "" {
		prefix = "llmhound-" + now.Format("20060102-150405")
	}

	// 1. Resolve correlation resolver if mapping file or AD domain suffixes exist
	resolver := s.resolver
	if resolver == nil && (s.cfg.Correlation.MappingFile != "" || len(s.cfg.Correlation.ADDomainSuffixes) > 0) {
		var mappings []correlate.Mapping
		if s.cfg.Correlation.MappingFile != "" {
			var err error
			mappings, err = correlate.LoadMappingFile(s.cfg.Correlation.MappingFile)
			if err != nil {
				return nil, fmt.Errorf("load correlation mapping file: %w", err)
			}
		}
		corrCfg := correlate.Config{
			Mappings:               mappings,
			ADSuffixes:             s.cfg.Correlation.ADDomainSuffixes,
			PropertyMatchSupported: true,
			ComputerProperty:       "name",
		}
		var err error
		resolver, err = correlate.New(corrCfg)
		if err != nil {
			return nil, fmt.Errorf("initialize correlation resolver: %w", err)
		}
	}

	// 2. Initialize checkpoint journal file
	journalPath := filepath.Join(outputDir, prefix+".journal.jsonl")
	header := checkpoint.Header{
		SchemaVersion:    "1",
		DeploymentScope:  s.cfg.Scope,
		ScanID:           scanID,
		CollectorVersion: s.collectorVersion,
		VantageKey:       s.cfg.VantageKey,
		CreatedAt:        now.Format(time.RFC3339),
	}

	journal, err := checkpoint.CreateFile(journalPath, header)
	if err != nil {
		return nil, fmt.Errorf("create checkpoint journal: %w", err)
	}

	// 3. Initialize collectors
	jupCfg := jupyter.Config{
		Scope:             s.cfg.Scope,
		VantageKey:        s.cfg.VantageKey,
		ScanID:            scanID,
		CollectorVersion:  s.collectorVersion,
		Bounds:            s.cfg.Bounds,
		Insecure:          s.cfg.Insecure,
		UserAgent:         s.cfg.UserAgent,
		Resolver:          resolver,
		VerifiedComputers: s.verifiedComputers,
		Now:               s.now,
		HTTPClient:        s.httpClient,
	}
	jupCol, err := jupyter.New(jupCfg)
	if err != nil {
		_ = journal.Close()
		return nil, fmt.Errorf("initialize jupyter collector: %w", err)
	}

	ollamaCol := ollama.New(s.cfg)

	mcpOpts := []collectormcp.Option{
		collectormcp.WithScanID(scanID),
		collectormcp.WithCollectorVersion(s.collectorVersion),
		collectormcp.WithClock(s.now),
	}
	if resolver != nil {
		mcpOpts = append(mcpOpts, collectormcp.WithCorrelator(resolver, s.verifiedComputers))
	}
	if s.httpClient != nil {
		mcpOpts = append(mcpOpts, collectormcp.WithHTTPClient(s.httpClient))
	}
	mcpCol, err := collectormcp.New(s.cfg, mcpOpts...)
	if err != nil {
		_ = journal.Close()
		return nil, fmt.Errorf("initialize mcp collector: %w", err)
	}

	vantage, err := graph.NewVantageIdentity(s.cfg.Scope, s.cfg.VantageKey)
	if err != nil {
		_ = journal.Close()
		return nil, fmt.Errorf("create vantage identity: %w", err)
	}

	// 5. Worker pool for bounded concurrency
	concurrency := s.cfg.Bounds.Concurrency
	if concurrency <= 0 {
		concurrency = 16
	}

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var recordMu sync.Mutex
	var firstRecordErr error
	recordFailure := func(err error) {
		recordMu.Lock()
		if firstRecordErr == nil {
			firstRecordErr = err
		}
		recordMu.Unlock()
	}
	record := func(res checkpoint.Result) {
		if err := journal.RecordResult(res); err != nil {
			recordFailure(err)
		}
	}

	for _, tgt := range targets {
		if ctx.Err() != nil {
			break
		}
		targetHost := tgt
		wg.Add(1)
		sem <- struct{}{}

		go func(host string) {
			defer wg.Done()
			defer func() { <-sem }()

			for _, def := range s.definitions {
				switch def.Surface {
				case discovery.SurfaceJupyter, discovery.SurfaceOllama, discovery.SurfaceMCP:
				default:
					continue
				}
				baseURL := discovery.BaseURLForHost(host, def.DefaultPort, false)

				probe, err := discovery.Probe(ctx, s.httpClient, baseURL, def)
				if err != nil {
					recordFailure(fmt.Errorf("probe %s %s: %w", def.Surface, host, err))
					continue
				}
				if !probe.Matched {
					record(unmatchedResult(host, baseURL, def.Surface, probe, vantage, scanID, s.collectorVersion, now))
					continue
				}

				switch def.Surface {
				case discovery.SurfaceJupyter:
					target := host
					if def.DefaultPort != 8888 {
						target = baseURL
					}
					res, err := jupCol.CollectIdentified(ctx, target)
					if err != nil {
						recordFailure(fmt.Errorf("jupyter collect %s: %w", host, err))
						continue
					}
					res.Target = host
					record(res)
				case discovery.SurfaceOllama:
					target := host
					if def.DefaultPort != 11434 {
						target = baseURL
					}
					res, err := ollamaCol.Collect(ctx, target, vantage, scanID, now, resolver, s.verifiedComputers)
					if err != nil {
						recordFailure(fmt.Errorf("ollama collect %s: %w", host, err))
						continue
					}
					res.Target = host
					record(res)
				case discovery.SurfaceMCP:
					mcpTarget := collectormcp.Target{
						URL:            baseURL,
						OriginalTarget: host,
						Transport:      "auto",
					}
					if _, err := mcpCol.CollectTarget(ctx, mcpTarget, journal); err != nil {
						recordFailure(fmt.Errorf("mcp collect %s: %w", host, err))
					}
				}
			}
		}(targetHost)
	}

	wg.Wait()

	if firstRecordErr == nil {
		firstRecordErr = ctx.Err()
	}
	if firstRecordErr != nil {
		_ = journal.Close()
		return nil, firstRecordErr
	}

	// 6. Close journal to ensure all writes are flushed to disk
	if closeErr := journal.Close(); closeErr != nil {
		return nil, fmt.Errorf("close checkpoint journal: %w", closeErr)
	}

	// 7. Replay journal file to reconstruct accumulated state
	state, err := checkpoint.ReplayFile(journalPath)
	if err != nil {
		return nil, fmt.Errorf("replay checkpoint journal: %w", err)
	}

	// 8. Emit OpenGraph payload and evidence sidecar
	artifacts, err := emitter.EmitScan(outputDir, prefix, state.Nodes(), state.Edges(), state.Evidence())
	if err != nil {
		return nil, fmt.Errorf("emit scan artifacts: %w", err)
	}

	return &ScanResult{
		ScanID:       scanID,
		Prefix:       prefix,
		OutputDir:    outputDir,
		JournalPath:  journalPath,
		Artifacts:    artifacts,
		TargetsCount: len(targets),
		State:        state,
	}, nil
}

func unmatchedResult(host, baseURL string, surface discovery.Surface, probe discovery.ProbeResult, vantage graph.Identity, scanID, collectorVersion string, now time.Time) checkpoint.Result {
	reason := "target not identified as " + string(surface) + ": " + probe.Reason
	if !probe.Reachable {
		reason = "target unreachable: " + probe.Reason
	}
	sum := sha256.Sum256([]byte(scanID + "|" + host + "|" + string(surface)))
	return checkpoint.Result{
		Target:  host,
		Surface: string(surface),
		Observation: graph.Observation{
			SchemaVersion:    "1",
			ScanID:           scanID,
			CollectorVersion: collectorVersion,
			EvidenceID:       "ev-" + string(surface) + "-" + hex.EncodeToString(sum[:8]),
			Source:           baseURL,
			Surface:          string(surface),
			ObservedAt:       now,
			Vantage:          vantage,
			Coverage:         graph.CoverageFailed,
			CoverageReason:   reason,
		},
		Status:  checkpoint.TargetStatusFailed,
		Error:   reason,
		Details: map[string]any{"endpoint": baseURL},
	}
}
