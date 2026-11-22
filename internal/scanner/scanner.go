package scanner

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
	"github.com/0x3df/LLMHound/internal/targets"
	"github.com/0x3df/LLMHound/internal/transport"
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
	// TargetErrors lists per-target collection errors (bounded). Each one was
	// journaled as a failed result, so `resume` retries it; the scan still
	// emitted everything else.
	TargetErrors []string
	// TargetErrorCount is the total number of target errors, including any
	// beyond the retained TargetErrors list.
	TargetErrorCount int
}

// maxRetainedTargetErrors bounds ScanResult.TargetErrors.
const maxRetainedTargetErrors = 1000

// Option configures Scanner behavior.
type Option func(*Scanner)

// WithDefinitions sets custom discovery fingerprint definitions.
func WithDefinitions(defs []discovery.Definition) Option {
	return func(s *Scanner) {
		s.definitions = defs
		s.customDefs = true
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

// WithTCPDialer overrides the TCP dialer used during Stage 1 open-port sweeps.
func WithTCPDialer(dialer discovery.TCPDialer) Option {
	return func(s *Scanner) {
		s.tcpDialer = dialer
	}
}

// WithPriorityObjectIDs supplies BloodHound native ObjectIDs (e.g. hosts on or
// near Tier 0) whose mapped targets are scanned in the highest-priority wave.
func WithPriorityObjectIDs(ids map[string]bool) Option {
	return func(s *Scanner) {
		if len(ids) == 0 {
			return
		}
		cp := make(map[string]bool, len(ids))
		for k, v := range ids {
			if v {
				cp[k] = true
			}
		}
		s.priorityObjectIDs = cp
	}
}

// WithEndpoints provides explicit pre-scanned host:port (and optional scheme)
// targets to probe directly across active definitions without port filtering.
func WithEndpoints(endpoints []targets.EndpointTarget) Option {
	return func(s *Scanner) {
		s.endpoints = append([]targets.EndpointTarget(nil), endpoints...)
	}
}

// WithNow sets the clock used for scan and observation timestamps.
func WithNow(now func() time.Time) Option {
	return func(s *Scanner) {
		s.now = now
	}
}

// WithProgress writes a one-line progress summary to w every interval while a
// scan or resume runs. A nil writer disables progress output.
func WithProgress(w io.Writer, interval time.Duration) Option {
	return func(s *Scanner) {
		s.progress = w
		s.progressInterval = interval
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
	customDefs        bool
	resolver          *correlate.Resolver
	httpClient        *http.Client
	tcpDialer         discovery.TCPDialer
	priorityObjectIDs map[string]bool
	endpoints         []targets.EndpointTarget
	now               func() time.Time
	collectorVersion  string
	progress          io.Writer
	progressInterval  time.Duration
	// collectFault is a test seam (see export_test.go) that injects a
	// collector error for chosen targets.
	collectFault func(surface discovery.Surface, host string) error
}

// New creates and initializes a Scanner instance.
func New(cfg config.Config, opts ...Option) (*Scanner, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	defs, err := discovery.DefinitionsForProfile(cfg.Scan.Profile, cfg.Scan.Surfaces)
	if err != nil {
		return nil, fmt.Errorf("select discovery profile: %w", err)
	}

	s := &Scanner{
		cfg:              cfg,
		definitions:      defs,
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
				Endpoint:  "/model/info, /settings",
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
				{
					CheckID:   ray.CheckNodes,
					Operation: ray.CheckNodes,
					Method:    http.MethodGet,
					Endpoint:  "/nodes?view=summary",
					Purpose:   "Retrieve alive worker host IPs (worker_hosts) without scheduling work",
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
					Purpose:   "Inspect auto-login posture. When auto-login is on, Langflow issues a superuser session token to the scanner and may log a superuser login; the token is discarded, never stored or used",
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
	if len(targets) == 0 && len(s.endpoints) == 0 {
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
	if len(targets) == 0 && len(s.endpoints) == 0 {
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
	targetHosts []string,
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

	var contentSink content.Sink = contentWriter
	secretsOnlyMode := strings.EqualFold(s.cfg.Content.Mode, config.ContentModeSecretsOnly)
	if secretsOnlyMode {
		contentSink = content.DiscardSink{}
	}

	var lookupObjID func(string) (string, bool)
	if resolver != nil {
		lookupObjID = resolver.ObjectIDForTarget
	}
	orderedTargets := targets.PrioritizeTargets(targetHosts, lookupObjID, s.priorityObjectIDs, s.cfg.Scan.MappedOnlyTargets)

	// 3. Initialize collectors. Every collector shares one transport: one
	// authorized-host list (prepared targets plus explicit endpoints, so
	// nothing outside the operator's input is ever contacted), one per-host
	// rate limiter, and one proxy policy.
	authorized := make([]string, 0, len(orderedTargets)+len(s.endpoints))
	authorized = append(authorized, orderedTargets...)
	for _, ep := range s.endpoints {
		authorized = append(authorized, ep.Host)
	}
	limiter := transport.NewHostRateLimiter(s.cfg.Bounds.PerHostRate)
	shared := transport.NewClient(transport.Config{
		Bounds:          s.cfg.Bounds,
		Insecure:        s.cfg.Insecure,
		UserAgent:       s.cfg.UserAgent,
		AuthorizedHosts: authorized,
		Proxy:           s.cfg.Proxy,
		RateLimiter:     limiter,
	})
	defer shared.CloseIdleConnections()

	jupCfg := jupyter.Config{
		Scope:            s.cfg.Scope,
		VantageKey:       s.cfg.VantageKey,
		ScanID:           scanID,
		CollectorVersion: s.collectorVersion,
		Bounds:           s.cfg.Bounds,
		Content:          s.cfg.Content,
		Secrets:          s.cfg.Secrets,
		ContentSink:      contentSink,
		Insecure:         s.cfg.Insecure,
		UserAgent:        s.cfg.UserAgent,
		Resolver:         resolver,
		Now:              s.now,
		HTTPClient:       s.httpClient,
		Proxy:            s.cfg.Proxy,
		RateLimiter:      limiter,
	}
	jupCol, err := jupyter.New(jupCfg)
	if err != nil {
		_ = journal.Close()
		_ = closeContent()
		return nil, fmt.Errorf("initialize jupyter collector: %w", err)
	}

	surfCfg := s.cfg
	surfCfg.Targets = authorized
	cols := &collectorSet{
		scanner:      s,
		scanID:       scanID,
		now:          now,
		resolver:     resolver,
		jupyter:      jupCol,
		ollama:       ollama.New(surfCfg, ollama.WithContentSink(contentSink), ollama.WithTransport(shared)),
		a2a:          a2a.New(surfCfg, a2a.WithContentSink(contentSink), a2a.WithTransport(shared)),
		vllm:         vllm.New(surfCfg, vllm.WithTransport(shared)),
		qdrant:       qdrant.New(surfCfg, qdrant.WithContentSink(contentSink), qdrant.WithTransport(shared)),
		litellm:      litellm.New(surfCfg, litellm.WithContentSink(contentSink), litellm.WithTransport(shared)),
		mlflow:       mlflow.New(surfCfg, mlflow.WithContentSink(contentSink), mlflow.WithTransport(shared)),
		openwebui:    openwebui.New(surfCfg, openwebui.WithContentSink(contentSink), openwebui.WithTransport(shared)),
		langserve:    langserve.New(surfCfg, langserve.WithContentSink(contentSink), langserve.WithTransport(shared)),
		ray:          ray.New(surfCfg, ray.WithContentSink(contentSink), ray.WithTransport(shared)),
		langflow:     langflow.New(surfCfg, langflow.WithContentSink(contentSink), langflow.WithTransport(shared)),
		flowise:      flowise.New(surfCfg, flowise.WithContentSink(contentSink), flowise.WithTransport(shared)),
		chromadb:     chromadb.New(surfCfg, chromadb.WithContentSink(contentSink), chromadb.WithTransport(shared)),
		openaicompat: openaicompat.New(surfCfg, openaicompat.WithTransport(shared)),
	}

	mcpOpts := []collectormcp.Option{
		collectormcp.WithScanID(scanID),
		collectormcp.WithCollectorVersion(s.collectorVersion),
		collectormcp.WithClock(s.now),
		collectormcp.WithContentSink(contentSink),
		collectormcp.WithCorrelator(resolver),
		collectormcp.WithHostRateLimiter(limiter),
	}
	if s.httpClient != nil {
		mcpOpts = append(mcpOpts, collectormcp.WithHTTPClient(s.httpClient))
	}
	mcpCol, err := collectormcp.New(surfCfg, mcpOpts...)
	if err != nil {
		_ = journal.Close()
		_ = closeContent()
		return nil, fmt.Errorf("initialize mcp collector: %w", err)
	}
	cols.mcp = mcpCol

	probeClient, err := s.probeHTTPClient(limiter)
	if err != nil {
		_ = journal.Close()
		_ = closeContent()
		return nil, err
	}
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

	var activeDefs []discovery.Definition
	for _, def := range s.definitions {
		if isSupportedSurface(def.Surface) {
			activeDefs = append(activeDefs, def)
		}
	}

	sweptPorts := discovery.UniquePorts(activeDefs, s.cfg.Scan.ExtraPorts)
	sweptPortsCSV := joinPortsCSV(sweptPorts)

	// Stage 1: Fast TCP open-port sweep across deduplicated ports (bypassed only
	// when a unit test injects a mock HTTP RoundTripper without a TCP dialer).
	var openPorts map[string]map[int]bool
	tcpSwept := false
	if len(orderedTargets) > 0 && len(sweptPorts) > 0 && (s.httpClient == nil || s.tcpDialer != nil) {
		tcpSwept = true
		var toSweep []string
		for _, host := range orderedTargets {
			if priorState != nil && priorState.IsHostSweptEmpty(host, sweptPorts) {
				continue
			}
			allCompleted := priorState != nil && len(activeDefs) > 0
			if allCompleted {
				for _, def := range activeDefs {
					if !priorState.IsCompleted(host, string(def.Surface)) {
						allCompleted = false
						break
					}
				}
			}
			if !allCompleted {
				toSweep = append(toSweep, host)
			}
		}
		openPorts = discovery.SweepOpenPorts(ctx, toSweep, sweptPorts, s.cfg.Bounds.TCPConcurrency, s.cfg.Bounds.TCPTimeout, s.tcpDialer)
	}

	// 5. Worker pool for bounded concurrency
	concurrency := s.cfg.Bounds.Concurrency
	if concurrency <= 0 {
		concurrency = 64
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

	// A failure confined to one target (an unexpected probe or collector
	// error) is journaled as a failed result for that target and the scan
	// continues; only journal failures and interruption abort the run. One bad
	// host must never discard the output of every other host, and because the
	// result is "failed", resume retries it.
	var targetErrMu sync.Mutex
	var targetErrs []string
	targetErrCount := 0
	targetFailure := func(host, baseURL string, surface discovery.Surface, err error) {
		if ctx.Err() != nil {
			return // interruption is reported once, with a resume hint
		}
		msg := fmt.Sprintf("%s %s: %v", surface, host, err)
		targetErrMu.Lock()
		targetErrCount++
		if len(targetErrs) < maxRetainedTargetErrors {
			targetErrs = append(targetErrs, msg)
		}
		targetErrMu.Unlock()
		record(collectorErrorResult(host, baseURL, surface, err, s.cfg.Scope, s.cfg.VantageKey, scanID, s.collectorVersion, now))
	}

	var hostsDone, servicesFound atomic.Int64
	totalUnits := len(orderedTargets) + len(s.endpoints)
	stopProgress := s.startProgress(ctx, totalUnits, &hostsDone, &servicesFound, func() int {
		targetErrMu.Lock()
		defer targetErrMu.Unlock()
		return targetErrCount
	})
	defer stopProgress()

	schemeMode := s.cfg.Scan.Scheme
	if strings.TrimSpace(schemeMode) == "" {
		schemeMode = config.SchemeAuto
	}

targetLoop:
	for _, tgt := range orderedTargets {
		if ctx.Err() != nil {
			break targetLoop
		}
		if priorState != nil && priorState.IsHostSweptEmpty(tgt, sweptPorts) {
			hostsDone.Add(1)
			continue
		}

		// Fast path: TCP sweep found zero open ports on this host.
		if tcpSwept && len(openPorts[tgt]) == 0 {
			allDone := priorState != nil && len(activeDefs) > 0
			if allDone {
				for _, def := range activeDefs {
					if !priorState.IsCompleted(tgt, string(def.Surface)) {
						allDone = false
						break
					}
				}
			}
			if !allDone {
				if !s.cfg.Scan.RecordUnmatched {
					if err := journal.RecordTarget(sweepEmptyTargetRecord(tgt, sweptPortsCSV, scanID, s.collectorVersion, s.cfg.VantageKey, now)); err != nil {
						recordFailure(err)
					}
				} else {
					for _, def := range activeDefs {
						if priorState != nil && priorState.IsCompleted(tgt, string(def.Surface)) {
							continue
						}
						baseURL := discovery.BaseURLForHost(tgt, def.DefaultPort, false)
						probe := discovery.ProbeResult{
							Matched:   false,
							Surface:   def.Surface,
							Reachable: false,
							Reason:    "target unreachable on TCP port sweep",
						}
						record(unmatchedResult(tgt, baseURL, def.Surface, probe, s.cfg.Scope, s.cfg.VantageKey, scanID, s.collectorVersion, now))
					}
				}
			}
			hostsDone.Add(1)
			continue
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
		hostOpen := openPorts[tgt]
		wg.Add(1)

		go func(host string, openMap map[int]bool) {
			defer wg.Done()
			defer hostsDone.Add(1)
			defer func() { <-sem }()

			cache := discovery.NewPortProbeCache()
			matchedHostPort := make(map[string]bool)
			// Journal status is keyed by (host, surface). Once a surface matched
			// on one port, an unmatched extra port must not overwrite that
			// result as "failed" (which made resume re-collect the host).
			matchedSurface := make(map[discovery.Surface]bool)

			for _, def := range activeDefs {
				// Build candidate ports for this definition: DefaultPort + ExtraPorts.
				var candidatePorts []int
				if !tcpSwept || openMap[def.DefaultPort] {
					candidatePorts = append(candidatePorts, def.DefaultPort)
				}
				for _, ep := range s.cfg.Scan.ExtraPorts {
					if ep == def.DefaultPort {
						continue
					}
					if !tcpSwept || openMap[ep] {
						candidatePorts = append(candidatePorts, ep)
					}
				}

				if len(candidatePorts) == 0 {
					if s.cfg.Scan.RecordUnmatched && (priorState == nil || !priorState.IsCompleted(host, string(def.Surface))) {
						baseURL := discovery.BaseURLForHost(host, def.DefaultPort, false)
						probe := discovery.ProbeResult{Matched: false, Surface: def.Surface, Reachable: false, Reason: "target port unreachable on TCP sweep"}
						record(unmatchedResult(host, baseURL, def.Surface, probe, s.cfg.Scope, s.cfg.VantageKey, scanID, s.collectorVersion, now))
					}
					continue
				}

				if priorState != nil && priorState.IsCompleted(host, string(def.Surface)) {
					if priorHasNodes[targetSurface{target: host, surface: string(def.Surface)}] {
						for _, p := range candidatePorts {
							matchedHostPort[fmt.Sprintf("%s:%d", host, p)] = true
						}
					}
					continue
				}

				for _, port := range candidatePorts {
					hostPortKey := fmt.Sprintf("%s:%d", host, port)
					if def.Surface == discovery.SurfaceOpenAICompatible && matchedHostPort[hostPortKey] {
						continue
					}

					probe, err := discovery.ProbeWithScheme(ctx, probeClient, host, port, schemeMode, def, cache)
					if err != nil {
						targetFailure(host, discovery.BaseURLForHost(host, port, false), def.Surface, fmt.Errorf("probe: %w", err))
						continue
					}
					if !probe.Matched {
						if matchedSurface[def.Surface] {
							continue
						}
						if probe.Reachable || s.cfg.Scan.RecordUnmatched {
							baseURL := probe.BaseURL
							if baseURL == "" {
								baseURL = discovery.BaseURLForHost(host, port, false)
							}
							record(unmatchedResult(host, baseURL, def.Surface, probe, s.cfg.Scope, s.cfg.VantageKey, scanID, s.collectorVersion, now))
						}
						continue
					}
					matchedHostPort[hostPortKey] = true
					matchedSurface[def.Surface] = true
					baseURL := probe.BaseURL
					if baseURL == "" {
						baseURL = discovery.BaseURLForHost(host, port, probe.Scheme == "https")
					}
					if err := cols.collect(ctx, def.Surface, host, baseURL, port, probe, journal, record); err != nil {
						targetFailure(host, baseURL, def.Surface, err)
					} else {
						servicesFound.Add(1)
					}
				}
			}
		}(targetHost, hostOpen)
	}

endpointLoop:
	for _, ep := range s.endpoints {
		if ctx.Err() != nil {
			break endpointLoop
		}
		select {
		case <-ctx.Done():
			break endpointLoop
		case sem <- struct{}{}:
		}
		if ctx.Err() != nil {
			<-sem
			break endpointLoop
		}
		epCopy := ep
		wg.Add(1)
		go func(endpoint targets.EndpointTarget) {
			defer wg.Done()
			defer hostsDone.Add(1)
			defer func() { <-sem }()

			cache := discovery.NewPortProbeCache()
			matchedPort := false
			mode := schemeMode
			if endpoint.Scheme != "" {
				mode = endpoint.Scheme
			}
			for _, def := range activeDefs {
				if def.Surface == discovery.SurfaceOpenAICompatible && matchedPort {
					continue
				}
				probe, err := discovery.ProbeWithScheme(ctx, probeClient, endpoint.Host, endpoint.Port, mode, def, cache)
				if err != nil {
					targetFailure(endpoint.Host, discovery.BaseURLForHost(endpoint.Host, endpoint.Port, false), def.Surface, fmt.Errorf("probe: %w", err))
					continue
				}
				if !probe.Matched {
					continue
				}
				matchedPort = true
				baseURL := probe.BaseURL
				if baseURL == "" {
					baseURL = discovery.BaseURLForHost(endpoint.Host, endpoint.Port, probe.Scheme == "https")
				}
				if err := cols.collect(ctx, def.Surface, endpoint.Host, baseURL, endpoint.Port, probe, journal, record); err != nil {
					targetFailure(endpoint.Host, baseURL, def.Surface, err)
				} else {
					servicesFound.Add(1)
				}
			}
		}(epCopy)
	}

	wg.Wait()

	if firstRecordErr == nil && ctx.Err() != nil {
		firstRecordErr = fmt.Errorf("scan interrupted; completed targets are saved, continue with `llmhound resume --journal %s`: %w", journalPath, ctx.Err())
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
	if secretsOnlyMode {
		writtenContentCount = 0
	}
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

	evalObs := graph.Observation{
		SchemaVersion:    "1",
		ScanID:           scanID,
		CollectorVersion: s.collectorVersion,
		EvidenceID:       "ev-enrich",
		Source:           "scanner_enrichment",
		Surface:          "correlation",
		ObservedAt:       now,
		DeploymentScope:  s.cfg.Scope,
		VantageKey:       s.cfg.VantageKey,
		Coverage:         graph.CoverageComplete,
	}

	// 7a. Resolve cross-host UsesBackend edges (populates P5).
	backendEdges := ResolveBackendEdges(s.cfg.Scope, nodes, resolver, evalObs)
	if len(backendEdges) > 0 {
		edges = append(edges, backendEdges...)
	}

	// 7a2. Link exposed credentials and Entra SSO identities to native AZApp nodes (populates P11/P12).
	idEdges, idEvs, err := ResolveIdentityEdges(s.cfg.Scope, nodes, evalObs)
	if err != nil {
		return nil, fmt.Errorf("resolve identity edges: %w", err)
	}
	if len(idEdges) > 0 {
		edges = append(edges, idEdges...)
		evRecords = append(evRecords, idEvs...)
	}

	// 7b. Derive flat risk_signals on AIService nodes (populates P9 & rapid triage).
	EnrichRiskSignals(nodes, edges)

	// 7c. Evaluate opt-in path-qualification rules (M2d).
	if len(s.cfg.PathQualification.EnabledRules) > 0 {
		ruleObs := evalObs
		ruleObs.EvidenceID = "ev-rules"
		ruleObs.Source = "path_qualification"
		ruleObs.Surface = "rules"
		inputTargets := make(map[string]bool, len(orderedTargets))
		for _, t := range orderedTargets {
			if pt, perr := graph.ParseTarget(t); perr == nil {
				inputTargets[pt.Value()] = true
			}
		}
		ruleEdges, ruleEv, err := rules.EvaluateWithOptions(s.cfg.PathQualification, nodes, edges, evRecords, ruleObs, rules.Options{
			Resolver: resolver,
			InFanoutScope: func(host string) bool {
				pt, perr := graph.ParseTarget(host)
				return perr == nil && inputTargets[pt.Value()]
			},
		})
		if err != nil {
			return nil, fmt.Errorf("evaluate path-qualification rules: %w", err)
		}
		edges = append(edges, ruleEdges...)
		evRecords = append(evRecords, ruleEv...)
	}

	// 7d. Filter graph nodes/edges for compact attack-path mode & mapped-only policy.
	emitNodes, emitEdges := emitter.FilterAttackPathGraph(nodes, edges, emitter.FilterOptions{
		CompactAttackPath: strings.EqualFold(s.cfg.Scan.GraphMode, config.GraphModeAttackPath),
		MappedOnly:        s.cfg.Scan.MappedOnly,
	})

	// 8. Emit OpenGraph payload and evidence sidecar
	artifacts, err := emitter.EmitScanWithOptions(outputDir, prefix, emitNodes, emitEdges, evRecords, emitter.EmitScanOptions{
		CompactJSON: s.cfg.Scan.CompactJSON,
	})
	if err != nil {
		return nil, fmt.Errorf("emit scan artifacts: %w", err)
	}

	recordedContentPath := ""
	if writtenContentCount > 0 {
		recordedContentPath = contentPath
	} else if !secretsOnlyMode && priorState != nil {
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
		TargetsCount: len(orderedTargets) + len(s.endpoints),
		State:        state,

		TargetErrors:     targetErrs,
		TargetErrorCount: targetErrCount,
	}, nil
}

type collectorSet struct {
	scanner      *Scanner
	scanID       string
	now          time.Time
	resolver     *correlate.Resolver
	jupyter      *jupyter.Collector
	ollama       *ollama.Collector
	mcp          *collectormcp.Collector
	a2a          *a2a.Collector
	vllm         *vllm.Collector
	qdrant       *qdrant.Collector
	litellm      *litellm.Collector
	mlflow       *mlflow.Collector
	openwebui    *openwebui.Collector
	langserve    *langserve.Collector
	ray          *ray.Collector
	langflow     *langflow.Collector
	flowise      *flowise.Collector
	chromadb     *chromadb.Collector
	openaicompat *openaicompat.Collector
}

func (c *collectorSet) collect(
	ctx context.Context,
	surface discovery.Surface,
	host, baseURL string,
	port int,
	probe discovery.ProbeResult,
	journal *checkpoint.FileJournal,
	record func(checkpoint.Result),
) error {
	targetFor := func(defaultPort int) string {
		if port != defaultPort || probe.Scheme == "https" {
			return baseURL
		}
		return host
	}

	if c.scanner.collectFault != nil {
		if err := c.scanner.collectFault(surface, host); err != nil {
			return err
		}
	}

	var res checkpoint.Result
	var err error

	switch surface {
	case discovery.SurfaceJupyter:
		res, err = c.jupyter.CollectIdentified(ctx, targetFor(8888))
	case discovery.SurfaceOllama:
		res, err = c.ollama.Collect(ctx, targetFor(ollama.DefaultPort), c.scanner.cfg.Scope, c.scanner.cfg.VantageKey, c.scanID, c.now, c.resolver)
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
		if _, cerr := c.mcp.CollectTarget(ctx, mcpTarget, journal); cerr != nil {
			return fmt.Errorf("mcp collect %s: %w", host, cerr)
		}
		return nil
	case discovery.SurfaceA2A:
		res, err = c.a2a.Collect(ctx, targetFor(a2a.DefaultPort), c.scanner.cfg.Scope, c.scanner.cfg.VantageKey, c.scanID, c.now, c.resolver)
	case discovery.SurfaceVLLM:
		res, err = c.vllm.Collect(ctx, targetFor(vllm.DefaultPort), c.scanner.cfg.Scope, c.scanner.cfg.VantageKey, c.scanID, c.now, c.resolver)
	case discovery.SurfaceQdrant:
		res, err = c.qdrant.Collect(ctx, targetFor(qdrant.DefaultPort), c.scanner.cfg.Scope, c.scanner.cfg.VantageKey, c.scanID, c.now, c.resolver)
	case discovery.SurfaceLiteLLM:
		res, err = c.litellm.Collect(ctx, targetFor(litellm.DefaultPort), c.scanner.cfg.Scope, c.scanner.cfg.VantageKey, c.scanID, c.now, c.resolver)
	case discovery.SurfaceMLflow:
		res, err = c.mlflow.Collect(ctx, targetFor(mlflow.DefaultPort), c.scanner.cfg.Scope, c.scanner.cfg.VantageKey, c.scanID, c.now, c.resolver)
	case discovery.SurfaceOpenWebUI:
		res, err = c.openwebui.Collect(ctx, targetFor(openwebui.DefaultPort), c.scanner.cfg.Scope, c.scanner.cfg.VantageKey, c.scanID, c.now, c.resolver)
	case discovery.SurfaceLangServe:
		res, err = c.langserve.Collect(ctx, targetFor(langserve.DefaultPort), c.scanner.cfg.Scope, c.scanner.cfg.VantageKey, c.scanID, c.now, c.resolver)
	case discovery.SurfaceRay:
		res, err = c.ray.Collect(ctx, targetFor(ray.DefaultPort), c.scanner.cfg.Scope, c.scanner.cfg.VantageKey, c.scanID, c.now, c.resolver)
	case discovery.SurfaceLangflow:
		res, err = c.langflow.Collect(ctx, targetFor(langflow.DefaultPort), c.scanner.cfg.Scope, c.scanner.cfg.VantageKey, c.scanID, c.now, c.resolver)
	case discovery.SurfaceFlowise:
		res, err = c.flowise.Collect(ctx, targetFor(flowise.DefaultPort), c.scanner.cfg.Scope, c.scanner.cfg.VantageKey, c.scanID, c.now, c.resolver)
	case discovery.SurfaceChromaDB:
		res, err = c.chromadb.Collect(ctx, targetFor(chromadb.DefaultPort), c.scanner.cfg.Scope, c.scanner.cfg.VantageKey, c.scanID, c.now, c.resolver)
	case discovery.SurfaceOpenAICompatible:
		res, err = c.openaicompat.Collect(ctx, targetFor(openaicompat.DefaultPort), c.scanner.cfg.Scope, c.scanner.cfg.VantageKey, c.scanID, c.now, c.resolver)
	default:
		return nil
	}

	if err != nil {
		return fmt.Errorf("%s collect %s: %w", surface, host, err)
	}
	res.Target = host
	record(res)
	return nil
}

func isSupportedSurface(s discovery.Surface) bool {
	switch s {
	case discovery.SurfaceJupyter, discovery.SurfaceOllama, discovery.SurfaceMCP,
		discovery.SurfaceA2A, discovery.SurfaceVLLM, discovery.SurfaceQdrant,
		discovery.SurfaceLiteLLM, discovery.SurfaceMLflow, discovery.SurfaceOpenWebUI, discovery.SurfaceLangServe,
		discovery.SurfaceRay, discovery.SurfaceLangflow, discovery.SurfaceFlowise,
		discovery.SurfaceChromaDB, discovery.SurfaceOpenAICompatible:
		return true
	}
	return false
}

func joinPortsCSV(ports []int) string {
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(p)
	}
	return strings.Join(parts, ",")
}

func sweepEmptyTargetRecord(host, sweptPortsCSV, scanID, collectorVersion, vantageKey string, now time.Time) checkpoint.TargetRecord {
	sum := sha256.Sum256([]byte(scanID + "|" + host + "|" + checkpoint.SweepMarkerSurface))
	return checkpoint.TargetRecord{
		Target:  host,
		Surface: checkpoint.SweepMarkerSurface,
		Status:  checkpoint.TargetStatusCompleted,
		Observation: &checkpoint.ObservationRecord{
			SchemaVersion:    "1",
			ScanID:           scanID,
			CollectorVersion: collectorVersion,
			EvidenceID:       "ev-sweep-" + hex.EncodeToString(sum[:8]),
			Source:           host,
			Surface:          checkpoint.SweepMarkerSurface,
			ObservedAt:       now.UTC().Format(time.RFC3339),
			VantageKey:       vantageKey,
			Coverage:         string(graph.CoverageComplete),
			CoverageReason:   "no open discovery ports on TCP sweep",
		},
		Details: map[string]any{"swept_ports": sweptPortsCSV},
	}
}

type uaTransport struct {
	base      http.RoundTripper
	userAgent string
}

// CloseIdleConnections forwards to the wrapped transport.
func (u uaTransport) CloseIdleConnections() {
	if c, ok := u.base.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}

func (u uaTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if u.userAgent != "" && req.Header.Get("User-Agent") == "" {
		req = req.Clone(req.Context())
		req.Header.Set("User-Agent", u.userAgent)
	}
	return u.base.RoundTrip(req)
}

// probeHTTPClient builds the discovery client. Probes share the scan-wide
// per-host limiter and the explicit proxy policy; environment proxy variables
// are ignored. TLS verification uses the platform trust store (the Windows
// certificate store on Windows) unless --insecure is set.
func (s *Scanner) probeHTTPClient(limiter *transport.HostRateLimiter) (*http.Client, error) {
	if s.httpClient != nil {
		return s.httpClient, nil
	}
	connectTimeout := s.cfg.Bounds.ConnectTimeout
	if connectTimeout <= 0 {
		connectTimeout = 3 * time.Second
	}
	responseTimeout := s.cfg.Bounds.ResponseTimeout
	if responseTimeout <= 0 {
		responseTimeout = 10 * time.Second
	}
	maxIdle := s.cfg.Bounds.Concurrency * 2
	if maxIdle < 64 {
		maxIdle = 64
	}
	proxy, err := transport.ProxyFunc(s.cfg.Proxy)
	if err != nil {
		return nil, fmt.Errorf("discovery client: %w", err)
	}
	tr := &http.Transport{
		Proxy:                 proxy,
		DialContext:           (&net.Dialer{Timeout: connectTimeout, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   connectTimeout,
		ResponseHeaderTimeout: responseTimeout,
		MaxIdleConns:          maxIdle,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       30 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: s.cfg.Insecure,
		},
	}
	return &http.Client{
		Transport: uaTransport{base: transport.RateLimitRoundTripper(tr, limiter), userAgent: s.cfg.UserAgent},
		Timeout:   responseTimeout,
	}, nil
}

// collectorErrorResult journals an unexpected per-target error as failed
// coverage so the target is reported honestly and retried on resume.
func collectorErrorResult(host, baseURL string, surface discovery.Surface, err error, scope, vantageKey, scanID, collectorVersion string, now time.Time) checkpoint.Result {
	reason := "collection error: " + err.Error()
	sum := sha256.Sum256([]byte(scanID + "|" + host + "|" + string(surface) + "|error"))
	return checkpoint.Result{
		Target:  host,
		Surface: string(surface),
		Observation: graph.Observation{
			SchemaVersion:    "1",
			ScanID:           scanID,
			CollectorVersion: collectorVersion,
			EvidenceID:       "ev-" + string(surface) + "-err-" + hex.EncodeToString(sum[:8]),
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

// startProgress prints a periodic progress line when WithProgress is set and
// returns a function that stops it and prints a final line.
func (s *Scanner) startProgress(ctx context.Context, total int, done, services *atomic.Int64, errs func() int) func() {
	if s.progress == nil {
		return func() {}
	}
	interval := s.progressInterval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	start := time.Now()
	line := func() {
		fmt.Fprintf(s.progress, "progress: %d/%d targets done, %d services collected, %d target errors, elapsed %s\n",
			done.Load(), total, services.Load(), errs(), time.Since(start).Round(time.Second))
	}
	stop := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				line()
			case <-stop:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
	return func() {
		close(stop)
		<-finished
		line()
	}
}

func unmatchedResult(host, baseURL string, surface discovery.Surface, probe discovery.ProbeResult, scope, vantageKey, scanID, collectorVersion string, now time.Time) checkpoint.Result {
	reason := "target not identified as " + string(surface) + ": " + probe.Reason
	switch {
	case probe.TLSFailed:
		// Invariant 2: a certificate failure stops collection and is recorded
		// as such, never as "unreachable".
		reason = "collection stopped, " + probe.Reason + " (trust the issuing CA on the collection host, or pass --insecure explicitly)"
	case !probe.Reachable:
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
