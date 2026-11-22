package scanner

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/0x3df/LLMHound/internal/checkpoint"
	"github.com/0x3df/LLMHound/internal/collectors/a2a"
	"github.com/0x3df/LLMHound/internal/collectors/chromadb"
	"github.com/0x3df/LLMHound/internal/collectors/flowise"
	"github.com/0x3df/LLMHound/internal/collectors/jupyter"
	"github.com/0x3df/LLMHound/internal/collectors/langflow"
	"github.com/0x3df/LLMHound/internal/collectors/langserve"
	"github.com/0x3df/LLMHound/internal/collectors/litellm"
	collectormcp "github.com/0x3df/LLMHound/internal/collectors/mcp"
	"github.com/0x3df/LLMHound/internal/collectors/mlflow"
	"github.com/0x3df/LLMHound/internal/collectors/ollama"
	"github.com/0x3df/LLMHound/internal/collectors/openaicompat"
	"github.com/0x3df/LLMHound/internal/collectors/openwebui"
	"github.com/0x3df/LLMHound/internal/collectors/qdrant"
	"github.com/0x3df/LLMHound/internal/collectors/ray"
	"github.com/0x3df/LLMHound/internal/collectors/vllm"
	"github.com/0x3df/LLMHound/internal/config"
	"github.com/0x3df/LLMHound/internal/content"
	"github.com/0x3df/LLMHound/internal/correlate"
	"github.com/0x3df/LLMHound/internal/discovery"
	"github.com/0x3df/LLMHound/internal/emitter"
	"github.com/0x3df/LLMHound/internal/graph"
	"github.com/0x3df/LLMHound/internal/rules"
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
	ContentPath  string
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

// WithResolver provides an explicit asset-mapping resolver, overriding the
// configured mapping file.
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
	cfg              config.Config
	definitions      []discovery.Definition
	resolver         *correlate.Resolver
	httpClient       *http.Client
	now              func() time.Time
	collectorVersion string
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

	for _, def := range s.definitions {
		sp := SurfacePlan{
			Surface: def.Surface,
			Port:    def.DefaultPort,
		}

		switch def.Surface {
		case discovery.SurfaceJupyter:
			contentActive := s.cfg.Content.EnabledFor("jupyter")
			fileContentCheck := PlannedCheck{
				CheckID:   jupyter.CheckIDFileContent,
				Operation: jupyter.OpFileContent,
				Method:    http.MethodGet,
				Endpoint:  "/api/contents/<path>?content=1",
				Purpose:   "Read bounded text/notebook bodies into restricted .content.jsonl",
				Active:    contentActive,
			}
			if !contentActive {
				fileContentCheck.SkipReason = "policy: content collection disabled"
			}
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
				fileContentCheck,
			}

		case discovery.SurfaceMCP:
			contentActive := s.cfg.Content.EnabledFor("mcp")
			resReadCheck := PlannedCheck{
				CheckID:   collectormcp.CheckIDResourcesRead,
				Operation: collectormcp.OpResourcesRead,
				Method:    http.MethodPost,
				Endpoint:  "/mcp",
				Purpose:   "Read bounded text resource bodies into restricted .content.jsonl",
				Active:    contentActive,
			}
			if !contentActive {
				resReadCheck.SkipReason = "policy: content collection disabled"
			}
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
				resReadCheck,
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
			contentActive := s.cfg.Content.EnabledFor("ollama")
			showCheck := PlannedCheck{
				CheckID:   ollama.CheckShow,
				Operation: "ollama_show",
				Method:    http.MethodPost,
				Endpoint:  "/api/show",
				Purpose:   "Retrieve redacted model provenance and bounded prompts/modelfiles into .content.jsonl",
				Active:    contentActive,
			}
			if !contentActive {
				showCheck.SkipReason = "policy: content collection disabled"
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

		case discovery.SurfaceA2A:
			sp.Checks = []PlannedCheck{
				{
					CheckID:   a2a.CheckAgentCard,
					Operation: a2a.CheckAgentCard,
					Method:    http.MethodGet,
					Endpoint:  "/.well-known/agent-card.json",
					Purpose:   "Retrieve public A2A agent card metadata, skills, and auth declarations",
					Active:    true,
				},
			}

		case discovery.SurfaceVLLM:
			sp.Checks = []PlannedCheck{
				{
					CheckID:   vllm.CheckVersion,
					Operation: vllm.CheckVersion,
					Method:    http.MethodGet,
					Endpoint:  "/version",
					Purpose:   "Retrieve reported vLLM runtime version",
					Active:    true,
				},
				{
					CheckID:   vllm.CheckModels,
					Operation: vllm.CheckModels,
					Method:    http.MethodGet,
					Endpoint:  "/v1/models",
					Purpose:   "Enumerate served models and aliases",
					Active:    true,
				},
			}

		case discovery.SurfaceQdrant:
			contentActive := s.cfg.Content.EnabledFor("qdrant")
			sampleCheck := PlannedCheck{
				CheckID:   qdrant.CheckPointsSample,
				Operation: qdrant.CheckPointsSample,
				Method:    http.MethodPost,
				Endpoint:  "/collections/<name>/points/scroll",
				Purpose:   "Collect bounded point payload samples (without vectors) into restricted .content.jsonl",
				Active:    contentActive,
			}
			if !contentActive {
				sampleCheck.SkipReason = "policy: content collection disabled"
			}
			sp.Checks = []PlannedCheck{
				{
					CheckID:   qdrant.CheckVersion,
					Operation: qdrant.CheckVersion,
					Method:    http.MethodGet,
					Endpoint:  "/",
					Purpose:   "Retrieve Qdrant version and build commit metadata",
					Active:    true,
				},
				{
					CheckID:   qdrant.CheckCollections,
					Operation: qdrant.CheckCollections,
					Method:    http.MethodGet,
					Endpoint:  "/collections",
					Purpose:   "Enumerate Qdrant vector collections",
					Active:    true,
				},
				{
					CheckID:   qdrant.CheckCollectionInfo,
					Operation: qdrant.CheckCollectionInfo,
					Method:    http.MethodGet,
					Endpoint:  "/collections/<name>",
					Purpose:   "Retrieve collection schema, counts, and vector dimensions",
					Active:    true,
				},
				{
					CheckID:   qdrant.CheckSnapshots,
					Operation: qdrant.CheckSnapshots,
					Method:    http.MethodGet,
					Endpoint:  "/snapshots",
					Purpose:   "Enumerate exposed Qdrant snapshot listings",
					Active:    true,
				},
				sampleCheck,
			}

		case discovery.SurfaceLiteLLM:
			contentActive := s.cfg.Content.EnabledFor(litellm.Surface)
			cfgCheck := PlannedCheck{
				CheckID:   litellm.CheckConfig,
				Operation: litellm.CheckConfig,
				Method:    http.MethodGet,
				Endpoint:  "/model/info",
				Purpose:   "Capture bounded LiteLLM configuration into restricted .content.jsonl",
				Active:    contentActive,
			}
			if !contentActive {
				cfgCheck.SkipReason = "policy: content collection disabled"
			}
			sp.Checks = []PlannedCheck{
				{
					CheckID:   litellm.CheckOpenAPI,
					Operation: litellm.CheckOpenAPI,
					Method:    http.MethodGet,
					Endpoint:  "/openapi.json",
					Purpose:   "Retrieve LiteLLM OpenAPI identity, API version, and key-management route advertisement",
					Active:    true,
				},
				{
					CheckID:   litellm.CheckModels,
					Operation: litellm.CheckModels,
					Method:    http.MethodGet,
					Endpoint:  "/v1/models",
					Purpose:   "Enumerate served models",
					Active:    true,
				},
				{
					CheckID:   litellm.CheckModelInfo,
					Operation: litellm.CheckModelInfo,
					Method:    http.MethodGet,
					Endpoint:  "/model/info",
					Purpose:   "Enumerate model provider aliases and sanitized backend references",
					Active:    true,
				},
				cfgCheck,
			}

		case discovery.SurfaceMLflow:
			contentActive := s.cfg.Content.EnabledFor(mlflow.Surface)
			artTextCheck := PlannedCheck{
				CheckID:   mlflow.CheckArtifactText,
				Operation: mlflow.CheckArtifactText,
				Method:    http.MethodGet,
				Endpoint:  "/get-artifact?path=<allowlisted_text>&run_id=<run_id>",
				Purpose:   "Read bounded allowlisted small text artifacts into restricted .content.jsonl",
				Active:    contentActive,
			}
			if !contentActive {
				artTextCheck.SkipReason = "policy: content collection disabled"
			}
			sp.Checks = []PlannedCheck{
				{
					CheckID:   mlflow.CheckVersion,
					Operation: mlflow.CheckVersion,
					Method:    http.MethodGet,
					Endpoint:  "/version",
					Purpose:   "Retrieve MLflow server version",
					Active:    true,
				},
				{
					CheckID:   mlflow.CheckExperiments,
					Operation: mlflow.CheckExperiments,
					Method:    http.MethodGet,
					Endpoint:  "/api/2.0/mlflow/experiments/search",
					Purpose:   "Enumerate MLflow experiments and sanitized artifact store roots",
					Active:    true,
				},
				{
					CheckID:   mlflow.CheckRegisteredModels,
					Operation: mlflow.CheckRegisteredModels,
					Method:    http.MethodGet,
					Endpoint:  "/api/2.0/mlflow/registered-models/search",
					Purpose:   "Enumerate registered models, versions, stages, and aliases",
					Active:    true,
				},
				{
					CheckID:   mlflow.CheckArtifactsList,
					Operation: mlflow.CheckArtifactsList,
					Method:    http.MethodGet,
					Endpoint:  "/api/2.0/mlflow/artifacts/list",
					Purpose:   "List artifact inventory for discovered model run IDs without downloading weights",
					Active:    true,
				},
				artTextCheck,
			}

		case discovery.SurfaceOpenWebUI:
			contentActive := s.cfg.Content.EnabledFor(openwebui.Surface)
			cfgContentCheck := PlannedCheck{
				CheckID:   openwebui.CheckConfigContent,
				Operation: openwebui.CheckConfigContent,
				Method:    http.MethodGet,
				Endpoint:  "/api/config",
				Purpose:   "Capture bounded Open WebUI configuration into restricted .content.jsonl",
				Active:    contentActive,
			}
			if !contentActive {
				cfgContentCheck.SkipReason = "policy: content collection disabled"
			}
			sp.Checks = []PlannedCheck{
				{
					CheckID:   openwebui.CheckVersion,
					Operation: openwebui.CheckVersion,
					Method:    http.MethodGet,
					Endpoint:  "/api/version",
					Purpose:   "Retrieve Open WebUI application version",
					Active:    true,
				},
				{
					CheckID:   openwebui.CheckConfig,
					Operation: openwebui.CheckConfig,
					Method:    http.MethodGet,
					Endpoint:  "/api/config",
					Purpose:   "Retrieve Open WebUI auth/signup settings and declared backend references",
					Active:    true,
				},
				{
					CheckID:   openwebui.CheckModels,
					Operation: openwebui.CheckModels,
					Method:    http.MethodGet,
					Endpoint:  "/api/models",
					Purpose:   "Enumerate models exposed by Open WebUI",
					Active:    true,
				},
				cfgContentCheck,
			}

		case discovery.SurfaceLangServe:
			sp.Checks = []PlannedCheck{
				{
					CheckID:   langserve.CheckOpenAPI,
					Operation: langserve.CheckOpenAPI,
					Method:    http.MethodGet,
					Endpoint:  "/openapi.json",
					Purpose:   "Enumerate LangServe runnable routes and OpenAPI version metadata",
					Active:    true,
				},
				{
					CheckID:   langserve.CheckSchemas,
					Operation: langserve.CheckSchemas,
					Method:    http.MethodGet,
					Endpoint:  "<route>/{input_schema,output_schema,config_schema}",
					Purpose:   "Retrieve runnable input/output/config JSON schemas",
					Active:    true,
				},
				{
					CheckID:   langserve.CheckPlayground,
					Operation: langserve.CheckPlayground,
					Method:    http.MethodGet,
					Endpoint:  "<route>/playground/",
					Purpose:   "Check whether LangServe playground is anonymously exposed",
					Active:    true,
				},
			}

		case discovery.SurfaceRay:
			contentActive := s.cfg.Content.EnabledFor(ray.Surface)
			jobContentCheck := PlannedCheck{
				CheckID:   ray.CheckJobContent,
				Operation: ray.CheckJobContent,
				Method:    http.MethodGet,
				Endpoint:  "/api/jobs/",
				Purpose:   "Capture bounded Ray job entrypoints and runtime_env into restricted .content.jsonl",
				Active:    contentActive,
			}
			if !contentActive {
				jobContentCheck.SkipReason = "policy: content collection disabled"
			}
			sp.Checks = []PlannedCheck{
				{
					CheckID:   ray.CheckVersion,
					Operation: ray.CheckVersion,
					Method:    http.MethodGet,
					Endpoint:  "/api/version",
					Purpose:   "Retrieve Ray version and commit metadata",
					Active:    true,
				},
				{
					CheckID:   ray.CheckClusterStatus,
					Operation: ray.CheckClusterStatus,
					Method:    http.MethodGet,
					Endpoint:  "/api/cluster_status",
					Purpose:   "Retrieve Ray cluster summary and node count",
					Active:    true,
				},
				{
					CheckID:   ray.CheckJobs,
					Operation: ray.CheckJobs,
					Method:    http.MethodGet,
					Endpoint:  "/api/jobs/",
					Purpose:   "Enumerate Ray jobs metadata without submitting jobs",
					Active:    true,
				},
				{
					CheckID:   ray.CheckActors,
					Operation: ray.CheckActors,
					Method:    http.MethodGet,
					Endpoint:  "/api/v0/actors",
					Purpose:   "Retrieve Ray actor count metadata",
					Active:    true,
				},
				jobContentCheck,
			}

		case discovery.SurfaceLangflow:
			contentActive := s.cfg.Content.EnabledFor(langflow.Surface)
			flowBodiesCheck := PlannedCheck{
				CheckID:   langflow.CheckFlowBodies,
				Operation: langflow.CheckFlowBodies,
				Method:    http.MethodGet,
				Endpoint:  "/api/v1/flows/",
				Purpose:   "Capture bounded Langflow flow bodies into restricted .content.jsonl",
				Active:    contentActive,
			}
			if !contentActive {
				flowBodiesCheck.SkipReason = "policy: content collection disabled"
			}
			sp.Checks = []PlannedCheck{
				{
					CheckID:   langflow.CheckVersion,
					Operation: langflow.CheckVersion,
					Method:    http.MethodGet,
					Endpoint:  "/api/v1/version",
					Purpose:   "Retrieve Langflow package version",
					Active:    true,
				},
				{
					CheckID:   langflow.CheckAutoLogin,
					Operation: langflow.CheckAutoLogin,
					Method:    http.MethodGet,
					Endpoint:  "/api/v1/auto_login",
					Purpose:   "Inspect auto-login posture without retaining token values",
					Active:    true,
				},
				{
					CheckID:   langflow.CheckFlows,
					Operation: langflow.CheckFlows,
					Method:    http.MethodGet,
					Endpoint:  "/api/v1/flows/",
					Purpose:   "Enumerate Langflow flow inventory without executing flows",
					Active:    true,
				},
				{
					CheckID:   langflow.CheckComponents,
					Operation: langflow.CheckComponents,
					Method:    http.MethodGet,
					Endpoint:  "/api/v1/all",
					Purpose:   "Enumerate Langflow component catalog counts",
					Active:    true,
				},
				flowBodiesCheck,
			}

		case discovery.SurfaceFlowise:
			contentActive := s.cfg.Content.EnabledFor(flowise.Surface)
			flowConfigCheck := PlannedCheck{
				CheckID:   flowise.CheckFlowConfig,
				Operation: flowise.CheckFlowConfig,
				Method:    http.MethodGet,
				Endpoint:  "/api/v1/chatflows",
				Purpose:   "Capture bounded Flowise chatflow definitions into restricted .content.jsonl",
				Active:    contentActive,
			}
			if !contentActive {
				flowConfigCheck.SkipReason = "policy: content collection disabled"
			}
			sp.Checks = []PlannedCheck{
				{
					CheckID:   flowise.CheckVersion,
					Operation: flowise.CheckVersion,
					Method:    http.MethodGet,
					Endpoint:  "/api/v1/version",
					Purpose:   "Retrieve Flowise version",
					Active:    true,
				},
				{
					CheckID:   flowise.CheckChatflows,
					Operation: flowise.CheckChatflows,
					Method:    http.MethodGet,
					Endpoint:  "/api/v1/chatflows",
					Purpose:   "Enumerate Flowise chatflows and public flags without calling predictions",
					Active:    true,
				},
				flowConfigCheck,
			}

		case discovery.SurfaceChromaDB:
			contentActive := s.cfg.Content.EnabledFor(chromadb.Surface)
			sampleCheck := PlannedCheck{
				CheckID:   chromadb.CheckDocumentsSample,
				Operation: chromadb.CheckDocumentsSample,
				Method:    http.MethodPost,
				Endpoint:  "/api/v2/.../collections/<id>/get",
				Purpose:   "Collect bounded document/metadata samples (without embeddings) into restricted .content.jsonl",
				Active:    contentActive,
			}
			if !contentActive {
				sampleCheck.SkipReason = "policy: content collection disabled"
			}
			sp.Checks = []PlannedCheck{
				{
					CheckID:   chromadb.CheckVersion,
					Operation: chromadb.CheckVersion,
					Method:    http.MethodGet,
					Endpoint:  "/api/v2/heartbeat",
					Purpose:   "Retrieve ChromaDB heartbeat and version",
					Active:    true,
				},
				{
					CheckID:   chromadb.CheckAuthIdentity,
					Operation: chromadb.CheckAuthIdentity,
					Method:    http.MethodGet,
					Endpoint:  "/api/v2/auth/identity",
					Purpose:   "Retrieve anonymous tenant and database identity",
					Active:    true,
				},
				{
					CheckID:   chromadb.CheckCollections,
					Operation: chromadb.CheckCollections,
					Method:    http.MethodGet,
					Endpoint:  "/api/v2/tenants/<tenant>/databases/<db>/collections",
					Purpose:   "Enumerate ChromaDB collections",
					Active:    true,
				},
				{
					CheckID:   chromadb.CheckCollectionCount,
					Operation: chromadb.CheckCollectionCount,
					Method:    http.MethodGet,
					Endpoint:  "/api/v2/.../collections/<id>/count",
					Purpose:   "Retrieve item counts per collection",
					Active:    true,
				},
				sampleCheck,
			}

		case discovery.SurfaceOpenAICompatible:
			sp.Checks = []PlannedCheck{
				{
					CheckID:   openaicompat.CheckModels,
					Operation: openaicompat.CheckModels,
					Method:    http.MethodGet,
					Endpoint:  "/v1/models",
					Purpose:   "Enumerate served models when no specific product is proven",
					Active:    true,
				},
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

	// 1. Resolve the asset-mapping resolver. Without a mapping every target
	// falls back to a NetworkEndpoint for the normalizer to attribute.
	resolver := s.resolver
	if resolver == nil {
		var err error
		resolver, err = correlate.NewFromConfig(s.cfg)
		if err != nil {
			return nil, fmt.Errorf("initialize correlation resolver: %w", err)
		}
	}

	// 2. Initialize checkpoint journal and lazy restricted content writer.
	// Never delete or truncate an existing content artifact: the journal is the
	// prefix owner, and a surviving content file is a collision.
	contentPath := filepath.Join(outputDir, prefix+".content.jsonl")
	if _, err := os.Lstat(contentPath); err == nil {
		return nil, fmt.Errorf("content artifact already exists: %w", os.ErrExist)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect content artifact: %w", err)
	}
	contentWriter := content.NewLazyFileWriter(contentPath)
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
		_ = contentWriter.Close()
		return nil, fmt.Errorf("create checkpoint journal: %w", err)
	}

	return s.runAndEmit(ctx, targets, outputDir, prefix, scanID, now, resolver, journalPath, journal, contentPath, contentWriter, nil)
}

// Resume continues an interrupted scan from an existing checkpoint journal,
// skipping already-completed (target, surface) pairs while preserving original
// observation timestamps, repairing any torn tail line, and re-emitting final
// OpenGraph, evidence, and content artifacts.
func (s *Scanner) Resume(ctx context.Context, journalPath string, targets []string, outputDir, prefix string) (*ScanResult, error) {
	if strings.TrimSpace(journalPath) == "" {
		return nil, fmt.Errorf("resume requires a journal path")
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets to scan")
	}

	priorState, replayErr := checkpoint.ReplayFile(journalPath)
	if replayErr != nil {
		var truncErr *checkpoint.TruncatedEntryError
		if !errors.As(replayErr, &truncErr) || priorState == nil {
			return nil, fmt.Errorf("replay checkpoint journal: %w", replayErr)
		}
	}

	hdr := priorState.Header()
	if hdr.DeploymentScope != s.cfg.Scope {
		return nil, fmt.Errorf("journal deployment_scope %q does not match config scope %q", hdr.DeploymentScope, s.cfg.Scope)
	}
	if hdr.VantageKey != s.cfg.VantageKey {
		return nil, fmt.Errorf("journal vantage_key %q does not match config vantage_key %q", hdr.VantageKey, s.cfg.VantageKey)
	}

	if outputDir == "" {
		outputDir = filepath.Dir(journalPath)
		if outputDir == "" {
			outputDir = "."
		}
	}
	if prefix == "" {
		base := filepath.Base(journalPath)
		prefix = strings.TrimSuffix(base, ".journal.jsonl")
		if prefix == base {
			prefix = strings.TrimSuffix(base, filepath.Ext(base))
		}
	}

	resolver := s.resolver
	if resolver == nil {
		var err error
		resolver, err = correlate.NewFromConfig(s.cfg)
		if err != nil {
			return nil, fmt.Errorf("initialize correlation resolver: %w", err)
		}
	}

	journal, err := checkpoint.OpenFile(journalPath)
	if err != nil {
		return nil, fmt.Errorf("open checkpoint journal for resume: %w", err)
	}

	contentPath := filepath.Join(outputDir, prefix+".content.jsonl")
	contentWriter := content.NewAppendLazyFileWriter(contentPath)
	now := s.now().UTC()

	return s.runAndEmit(ctx, targets, outputDir, prefix, hdr.ScanID, now, resolver, journalPath, journal, contentPath, contentWriter, priorState)
}

func (s *Scanner) runAndEmit(
	ctx context.Context,
	targets []string,
	outputDir, prefix, scanID string,
	now time.Time,
	resolver *correlate.Resolver,
	journalPath string,
	journal *checkpoint.FileJournal,
	contentPath string,
	contentWriter *content.LazyFileWriter,
	priorState *checkpoint.State,
) (*ScanResult, error) {
	closeContent := func() error { return contentWriter.Close() }

	// 3. Initialize collectors
	jupCfg := jupyter.Config{
		Scope:            s.cfg.Scope,
		VantageKey:       s.cfg.VantageKey,
		ScanID:           scanID,
		CollectorVersion: s.collectorVersion,
		Bounds:           s.cfg.Bounds,
		Content:          s.cfg.Content,
		Secrets:          s.cfg.Secrets,
		ContentSink:      contentWriter,
		Insecure:         s.cfg.Insecure,
		UserAgent:        s.cfg.UserAgent,
		Resolver:         resolver,
		Now:              s.now,
		HTTPClient:       s.httpClient,
	}
	jupCol, err := jupyter.New(jupCfg)
	if err != nil {
		_ = journal.Close()
		_ = closeContent()
		return nil, fmt.Errorf("initialize jupyter collector: %w", err)
	}

	surfCfg := s.cfg
	surfCfg.Targets = append([]string(nil), targets...)
	ollamaCol := ollama.New(surfCfg, ollama.WithContentSink(contentWriter))
	a2aCol := a2a.New(surfCfg, a2a.WithContentSink(contentWriter))
	vllmCol := vllm.New(surfCfg)
	qdrantCol := qdrant.New(surfCfg, qdrant.WithContentSink(contentWriter))
	litellmCol := litellm.New(surfCfg, litellm.WithContentSink(contentWriter))
	mlflowCol := mlflow.New(surfCfg, mlflow.WithContentSink(contentWriter))
	openwebuiCol := openwebui.New(surfCfg, openwebui.WithContentSink(contentWriter))
	langserveCol := langserve.New(surfCfg, langserve.WithContentSink(contentWriter))
	rayCol := ray.New(surfCfg, ray.WithContentSink(contentWriter))
	langflowCol := langflow.New(surfCfg, langflow.WithContentSink(contentWriter))
	flowiseCol := flowise.New(surfCfg, flowise.WithContentSink(contentWriter))
	chromadbCol := chromadb.New(surfCfg, chromadb.WithContentSink(contentWriter))
	openaiCompatCol := openaicompat.New(surfCfg)

	mcpOpts := []collectormcp.Option{
		collectormcp.WithScanID(scanID),
		collectormcp.WithCollectorVersion(s.collectorVersion),
		collectormcp.WithClock(s.now),
		collectormcp.WithContentSink(contentWriter),
	}
	mcpOpts = append(mcpOpts, collectormcp.WithCorrelator(resolver))
	if s.httpClient != nil {
		mcpOpts = append(mcpOpts, collectormcp.WithHTTPClient(s.httpClient))
	}
	mcpCol, err := collectormcp.New(s.cfg, mcpOpts...)
	if err != nil {
		_ = journal.Close()
		_ = closeContent()
		return nil, fmt.Errorf("initialize mcp collector: %w", err)
	}

	probeClient := s.probeHTTPClient()
	defer probeClient.CloseIdleConnections()

	type targetSurface struct {
		target  string
		surface string
	}
	priorHasNodes := make(map[targetSurface]bool)
	if priorState != nil {
		for _, prev := range priorState.Results() {
			if len(prev.Nodes) > 0 {
				priorHasNodes[targetSurface{target: prev.Target, surface: prev.Surface}] = true
			}
		}
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

targetLoop:
	for _, tgt := range targets {
		if ctx.Err() != nil {
			break targetLoop
		}
		select {
		case <-ctx.Done():
			break targetLoop
		case sem <- struct{}{}:
		}
		if ctx.Err() != nil {
			<-sem
			break targetLoop
		}
		targetHost := tgt
		wg.Add(1)

		go func(host string) {
			defer wg.Done()
			defer func() { <-sem }()

			matchedHostPort := make(map[string]bool)
			for _, def := range s.definitions {
				switch def.Surface {
				case discovery.SurfaceJupyter, discovery.SurfaceOllama, discovery.SurfaceMCP,
					discovery.SurfaceA2A, discovery.SurfaceVLLM, discovery.SurfaceQdrant,
					discovery.SurfaceLiteLLM, discovery.SurfaceMLflow, discovery.SurfaceOpenWebUI, discovery.SurfaceLangServe,
					discovery.SurfaceRay, discovery.SurfaceLangflow, discovery.SurfaceFlowise,
					discovery.SurfaceChromaDB, discovery.SurfaceOpenAICompatible:
				default:
					continue
				}
				hostPortKey := fmt.Sprintf("%s:%d", host, def.DefaultPort)
				if def.Surface == discovery.SurfaceOpenAICompatible && matchedHostPort[hostPortKey] {
					continue
				}
				if priorState != nil && priorState.IsCompleted(host, string(def.Surface)) {
					if priorHasNodes[targetSurface{target: host, surface: string(def.Surface)}] {
						matchedHostPort[hostPortKey] = true
					}
					continue
				}
				baseURL := discovery.BaseURLForHost(host, def.DefaultPort, false)

				probe, err := discovery.Probe(ctx, probeClient, baseURL, def)
				if err != nil {
					recordFailure(fmt.Errorf("probe %s %s: %w", def.Surface, host, err))
					continue
				}
				if !probe.Matched {
					record(unmatchedResult(host, baseURL, def.Surface, probe, s.cfg.Scope, s.cfg.VantageKey, scanID, s.collectorVersion, now))
					continue
				}
				matchedHostPort[hostPortKey] = true

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
					res, err := ollamaCol.Collect(ctx, target, s.cfg.Scope, s.cfg.VantageKey, scanID, now, resolver)
					if err != nil {
						recordFailure(fmt.Errorf("ollama collect %s: %w", host, err))
						continue
					}
					res.Target = host
					record(res)
				case discovery.SurfaceMCP:
					mcpURL := baseURL
					if probe.MatchedPath == "/mcp" || probe.MatchedPath == "/sse" {
						mcpURL = strings.TrimSuffix(baseURL, "/") + probe.MatchedPath
					}
					mcpTarget := collectormcp.Target{
						URL:            mcpURL,
						OriginalTarget: host,
						Transport:      "auto",
					}
					if _, err := mcpCol.CollectTarget(ctx, mcpTarget, journal); err != nil {
						recordFailure(fmt.Errorf("mcp collect %s: %w", host, err))
					}
				case discovery.SurfaceA2A:
					target := host
					if def.DefaultPort != a2a.DefaultPort {
						target = baseURL
					}
					res, err := a2aCol.Collect(ctx, target, s.cfg.Scope, s.cfg.VantageKey, scanID, now, resolver)
					if err != nil {
						recordFailure(fmt.Errorf("a2a collect %s: %w", host, err))
						continue
					}
					res.Target = host
					record(res)
				case discovery.SurfaceVLLM:
					target := host
					if def.DefaultPort != vllm.DefaultPort {
						target = baseURL
					}
					res, err := vllmCol.Collect(ctx, target, s.cfg.Scope, s.cfg.VantageKey, scanID, now, resolver)
					if err != nil {
						recordFailure(fmt.Errorf("vllm collect %s: %w", host, err))
						continue
					}
					res.Target = host
					record(res)
				case discovery.SurfaceQdrant:
					target := host
					if def.DefaultPort != qdrant.DefaultPort {
						target = baseURL
					}
					res, err := qdrantCol.Collect(ctx, target, s.cfg.Scope, s.cfg.VantageKey, scanID, now, resolver)
					if err != nil {
						recordFailure(fmt.Errorf("qdrant collect %s: %w", host, err))
						continue
					}
					res.Target = host
					record(res)
				case discovery.SurfaceLiteLLM:
					target := host
					if def.DefaultPort != litellm.DefaultPort {
						target = baseURL
					}
					res, err := litellmCol.Collect(ctx, target, s.cfg.Scope, s.cfg.VantageKey, scanID, now, resolver)
					if err != nil {
						recordFailure(fmt.Errorf("litellm collect %s: %w", host, err))
						continue
					}
					res.Target = host
					record(res)
				case discovery.SurfaceMLflow:
					target := host
					if def.DefaultPort != mlflow.DefaultPort {
						target = baseURL
					}
					res, err := mlflowCol.Collect(ctx, target, s.cfg.Scope, s.cfg.VantageKey, scanID, now, resolver)
					if err != nil {
						recordFailure(fmt.Errorf("mlflow collect %s: %w", host, err))
						continue
					}
					res.Target = host
					record(res)
				case discovery.SurfaceOpenWebUI:
					target := host
					if def.DefaultPort != openwebui.DefaultPort {
						target = baseURL
					}
					res, err := openwebuiCol.Collect(ctx, target, s.cfg.Scope, s.cfg.VantageKey, scanID, now, resolver)
					if err != nil {
						recordFailure(fmt.Errorf("open_webui collect %s: %w", host, err))
						continue
					}
					res.Target = host
					record(res)
				case discovery.SurfaceLangServe:
					target := host
					if def.DefaultPort != langserve.DefaultPort {
						target = baseURL
					}
					res, err := langserveCol.Collect(ctx, target, s.cfg.Scope, s.cfg.VantageKey, scanID, now, resolver)
					if err != nil {
						recordFailure(fmt.Errorf("langserve collect %s: %w", host, err))
						continue
					}
					res.Target = host
					record(res)
				case discovery.SurfaceRay:
					target := host
					if def.DefaultPort != ray.DefaultPort {
						target = baseURL
					}
					res, err := rayCol.Collect(ctx, target, s.cfg.Scope, s.cfg.VantageKey, scanID, now, resolver)
					if err != nil {
						recordFailure(fmt.Errorf("ray collect %s: %w", host, err))
						continue
					}
					res.Target = host
					record(res)
				case discovery.SurfaceLangflow:
					target := host
					if def.DefaultPort != langflow.DefaultPort {
						target = baseURL
					}
					res, err := langflowCol.Collect(ctx, target, s.cfg.Scope, s.cfg.VantageKey, scanID, now, resolver)
					if err != nil {
						recordFailure(fmt.Errorf("langflow collect %s: %w", host, err))
						continue
					}
					res.Target = host
					record(res)
				case discovery.SurfaceFlowise:
					target := host
					if def.DefaultPort != flowise.DefaultPort {
						target = baseURL
					}
					res, err := flowiseCol.Collect(ctx, target, s.cfg.Scope, s.cfg.VantageKey, scanID, now, resolver)
					if err != nil {
						recordFailure(fmt.Errorf("flowise collect %s: %w", host, err))
						continue
					}
					res.Target = host
					record(res)
				case discovery.SurfaceChromaDB:
					target := host
					if def.DefaultPort != chromadb.DefaultPort {
						target = baseURL
					}
					res, err := chromadbCol.Collect(ctx, target, s.cfg.Scope, s.cfg.VantageKey, scanID, now, resolver)
					if err != nil {
						recordFailure(fmt.Errorf("chromadb collect %s: %w", host, err))
						continue
					}
					res.Target = host
					record(res)
				case discovery.SurfaceOpenAICompatible:
					target := host
					if def.DefaultPort != openaicompat.DefaultPort {
						target = baseURL
					}
					res, err := openaiCompatCol.Collect(ctx, target, s.cfg.Scope, s.cfg.VantageKey, scanID, now, resolver)
					if err != nil {
						recordFailure(fmt.Errorf("openai_compatible collect %s: %w", host, err))
						continue
					}
					res.Target = host
					record(res)
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
		_ = closeContent()
		return nil, firstRecordErr
	}

	// 6. Close journal and content writer to flush writes to disk
	if closeErr := journal.Close(); closeErr != nil {
		_ = closeContent()
		return nil, fmt.Errorf("close checkpoint journal: %w", closeErr)
	}
	writtenContentCount := contentWriter.Count()
	if closeErr := closeContent(); closeErr != nil {
		return nil, fmt.Errorf("close content file: %w", closeErr)
	}

	// 7. Replay journal file to reconstruct accumulated state
	state, err := checkpoint.ReplayFile(journalPath)
	if err != nil {
		return nil, fmt.Errorf("replay checkpoint journal: %w", err)
	}

	nodes := state.Nodes()
	edges := state.Edges()
	evRecords := state.Evidence()

	// 7b. Evaluate opt-in path-qualification rules (M2d).
	if len(s.cfg.PathQualification.EnabledRules) > 0 {
		evalObs := graph.Observation{
			SchemaVersion:    "1",
			ScanID:           scanID,
			CollectorVersion: s.collectorVersion,
			EvidenceID:       "ev-rules",
			Source:           "path_qualification",
			Surface:          "rules",
			ObservedAt:       now,
			DeploymentScope:  s.cfg.Scope,
			VantageKey:       s.cfg.VantageKey,
			Coverage:         graph.CoverageComplete,
		}
		ruleEdges, ruleEv, err := rules.Evaluate(s.cfg.PathQualification, nodes, edges, evRecords, evalObs)
		if err != nil {
			return nil, fmt.Errorf("evaluate path-qualification rules: %w", err)
		}
		edges = append(edges, ruleEdges...)
		evRecords = append(evRecords, ruleEv...)
	}

	// 8. Emit OpenGraph payload and evidence sidecar
	artifacts, err := emitter.EmitScan(outputDir, prefix, nodes, edges, evRecords)
	if err != nil {
		return nil, fmt.Errorf("emit scan artifacts: %w", err)
	}

	recordedContentPath := ""
	if writtenContentCount > 0 {
		recordedContentPath = contentPath
	} else if priorState != nil {
		if _, statErr := os.Stat(contentPath); statErr == nil {
			recordedContentPath = contentPath
		}
	}

	return &ScanResult{
		ScanID:       scanID,
		Prefix:       prefix,
		OutputDir:    outputDir,
		JournalPath:  journalPath,
		ContentPath:  recordedContentPath,
		Artifacts:    artifacts,
		TargetsCount: len(targets),
		State:        state,
	}, nil
}

type uaTransport struct {
	base      http.RoundTripper
	userAgent string
}

func (u uaTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if u.userAgent != "" && req.Header.Get("User-Agent") == "" {
		req = req.Clone(req.Context())
		req.Header.Set("User-Agent", u.userAgent)
	}
	return u.base.RoundTrip(req)
}

func (s *Scanner) probeHTTPClient() *http.Client {
	if s.httpClient != nil {
		return s.httpClient
	}
	connectTimeout := s.cfg.Bounds.ConnectTimeout
	if connectTimeout <= 0 {
		connectTimeout = 3 * time.Second
	}
	responseTimeout := s.cfg.Bounds.ResponseTimeout
	if responseTimeout <= 0 {
		responseTimeout = 10 * time.Second
	}
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: connectTimeout, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   connectTimeout,
		ResponseHeaderTimeout: responseTimeout,
		MaxIdleConns:          64,
		IdleConnTimeout:       30 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: s.cfg.Insecure,
		},
	}
	return &http.Client{
		Transport: uaTransport{base: tr, userAgent: s.cfg.UserAgent},
		Timeout:   responseTimeout,
	}
}

func unmatchedResult(host, baseURL string, surface discovery.Surface, probe discovery.ProbeResult, scope, vantageKey, scanID, collectorVersion string, now time.Time) checkpoint.Result {
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
			DeploymentScope:  scope,
			VantageKey:       vantageKey,
			Coverage:         graph.CoverageFailed,
			CoverageReason:   reason,
		},
		Status:  checkpoint.TargetStatusFailed,
		Error:   reason,
		Details: map[string]any{"endpoint": baseURL},
	}
}
