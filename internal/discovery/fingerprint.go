package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Surface identifies a supported AI infrastructure service.
type Surface string

const (
	SurfaceJupyter          Surface = "jupyter"
	SurfaceOllama           Surface = "ollama"
	SurfaceMCP              Surface = "mcp"
	SurfaceA2A              Surface = "a2a"
	SurfaceVLLM             Surface = "vllm"
	SurfaceQdrant           Surface = "qdrant"
	SurfaceLiteLLM          Surface = "litellm"
	SurfaceMLflow           Surface = "mlflow"
	SurfaceOpenWebUI        Surface = "open_webui"
	SurfaceLangServe        Surface = "langserve"
	SurfaceRay              Surface = "ray"
	SurfaceLangflow         Surface = "langflow"
	SurfaceFlowise          Surface = "flowise"
	SurfaceChromaDB         Surface = "chromadb"
	SurfaceOpenAICompatible Surface = "openai_compatible"
)

// MatchFunc inspects an HTTP probe response to verify a service match.
type MatchFunc func(statusCode int, headers http.Header, body []byte) bool

// Definition defines data-driven fingerprinting rules for a surface.
type Definition struct {
	Surface     Surface
	DefaultPort int
	ProbePaths  []string
	Match       MatchFunc
}

// BuiltinDefinitions returns embedded discovery definitions.
// Generic OpenAI-compatible is placed last so specific surfaces match first.
func BuiltinDefinitions() []Definition {
	return []Definition{
		JupyterDefinition(),
		OllamaDefinition(),
		MCPDefinition(),
		A2ADefinition(),
		VLLMDefinition(),
		QdrantDefinition(),
		LiteLLMDefinition(),
		MLflowDefinition(),
		OpenWebUIDefinition(),
		LangServeDefinition(),
		RayDefinition(),
		LangflowDefinition(),
		FlowiseDefinition(),
		ChromaDBDefinition(),
		OpenAICompatibleDefinition(),
	}
}

// DefinitionForSurface returns the embedded definition for the given surface.
func DefinitionForSurface(surface Surface) (Definition, bool) {
	for _, def := range BuiltinDefinitions() {
		if def.Surface == surface {
			return def, true
		}
	}
	return Definition{}, false
}

// OllamaDefinition returns the fingerprint definition for Ollama LLM server.
func OllamaDefinition() Definition {
	return Definition{
		Surface:     SurfaceOllama,
		DefaultPort: 11434,
		ProbePaths:  []string{"/api/version", "/api/tags", "/"},
		Match: func(status int, headers http.Header, body []byte) bool {
			serverHeader := strings.ToLower(headers.Get("Server"))
			if strings.Contains(serverHeader, "ollama") {
				return true
			}
			bodyStr := strings.ToLower(string(body))
			if status == http.StatusOK {
				if strings.Contains(bodyStr, "ollama is running") {
					return true
				}
				var doc map[string]json.RawMessage
				if json.Unmarshal(body, &doc) == nil {
					if _, ok := doc["version"]; ok && len(doc) == 1 {
						return true
					}
					if _, ok := doc["models"]; ok && len(doc) == 1 {
						return true
					}
				}
			}
			if status == http.StatusUnauthorized || status == http.StatusForbidden {
				if strings.Contains(bodyStr, "ollama") {
					return true
				}
			}
			return false
		},
	}
}

// MCPDefinition returns the fingerprint definition for Model Context Protocol servers.
func MCPDefinition() Definition {
	return Definition{
		Surface:     SurfaceMCP,
		DefaultPort: 8080,
		ProbePaths:  []string{"/mcp", "/sse", "/", "/.well-known/oauth-protected-resource"},
		Match: func(status int, headers http.Header, body []byte) bool {
			contentType := strings.ToLower(headers.Get("Content-Type"))
			if strings.Contains(contentType, "text/event-stream") {
				return true
			}
			if headers.Get("Mcp-Session-Id") != "" {
				return true
			}
			authHeader := strings.ToLower(headers.Get("Www-Authenticate"))
			if strings.Contains(authHeader, "resource_metadata") {
				return true
			}
			bodyStr := strings.ToLower(string(body))
			if status >= http.StatusBadRequest && status < http.StatusInternalServerError && strings.Contains(bodyStr, "mcp-session-id") {
				return true
			}
			if strings.Contains(bodyStr, `"jsonrpc"`) {
				return true
			}
			if strings.Contains(bodyStr, `"authorization_servers"`) {
				return true
			}
			return false
		},
	}
}

// BaseURLForHost constructs a canonical base URL from host, port, and security setting.
func BaseURLForHost(host string, port int, secure bool) string {
	scheme := "http"
	if secure {
		scheme = "https"
	}
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return fmt.Sprintf("%s://[%s]:%d", scheme, host, port)
	}
	return fmt.Sprintf("%s://%s:%d", scheme, host, port)
}

// ProbeHost probes a target host against a definition using its default port.
func ProbeHost(ctx context.Context, client *http.Client, host string, def Definition, secure bool) (ProbeResult, error) {
	baseURL := BaseURLForHost(host, def.DefaultPort, secure)
	return Probe(ctx, client, baseURL, def)
}

// JupyterDefinition returns the fingerprint definition for Jupyter Server / Notebook.
func JupyterDefinition() Definition {
	return Definition{
		Surface:     SurfaceJupyter,
		DefaultPort: 8888,
		ProbePaths:  []string{"/api", "/api/status", "/tree", "/login"},
		Match: func(status int, headers http.Header, body []byte) bool {
			serverHeader := strings.ToLower(headers.Get("Server"))
			if strings.Contains(serverHeader, "jupyter") {
				return true
			}
			if headers.Get("X-Jupyter-Version") != "" {
				return true
			}
			bodyStr := strings.ToLower(string(body))
			// Status 200 with JSON version or status
			if status == http.StatusOK {
				if strings.Contains(bodyStr, `"version"`) && strings.Contains(bodyStr, "jupyter") {
					return true
				}
				if strings.Contains(bodyStr, `"kernels"`) && strings.Contains(bodyStr, `"connections"`) {
					return true
				}
				if strings.Contains(bodyStr, "jupyter notebook") || strings.Contains(bodyStr, "jupyter server") || strings.Contains(bodyStr, "jupyterlab") {
					return true
				}
			}
			// Status 401 / 403
			if status == http.StatusUnauthorized || status == http.StatusForbidden {
				if strings.Contains(bodyStr, "jupyter") {
					return true
				}
			}
			// Redirect to login or tree
			if status == http.StatusFound || status == http.StatusSeeOther || status == http.StatusTemporaryRedirect {
				if IsJupyterLoginRedirect(headers.Get("Location")) {
					return true
				}
			}
			return false
		},
	}
}

// IsJupyterLoginRedirect reports whether a Location value is a Jupyter-style login
// redirect: a /login path whose next parameter targets a /tree or /lab page.
func IsJupyterLoginRedirect(location string) bool {
	u, err := url.Parse(location)
	if err != nil || !strings.HasSuffix(strings.TrimRight(u.Path, "/"), "/login") {
		return false
	}
	next := strings.ToLower(u.Query().Get("next"))
	return strings.Contains(next, "/tree") || strings.Contains(next, "/lab")
}

// A2ADefinition returns the fingerprint definition for Agent2Agent (A2A) endpoints.
func A2ADefinition() Definition {
	return Definition{
		Surface:     SurfaceA2A,
		DefaultPort: 8080,
		ProbePaths:  []string{"/.well-known/agent-card.json", "/.well-known/agent.json"},
		Match: func(status int, headers http.Header, body []byte) bool {
			bodyStr := strings.ToLower(string(body))
			if status == http.StatusOK {
				var doc map[string]json.RawMessage
				if json.Unmarshal(body, &doc) != nil {
					return false
				}
				var name string
				if rawName, ok := doc["name"]; !ok || json.Unmarshal(rawName, &name) != nil || strings.TrimSpace(name) == "" {
					return false
				}
				for _, key := range []string{"skills", "capabilities", "protocolVersion", "defaultInputModes", "supportedInterfaces", "additionalInterfaces"} {
					if _, ok := doc[key]; ok {
						return true
					}
				}
				if _, hasURL := doc["url"]; hasURL {
					for _, key := range []string{"security", "securitySchemes", "version"} {
						if _, ok := doc[key]; ok {
							return true
						}
					}
				}
				return false
			}
			if status == http.StatusUnauthorized || status == http.StatusForbidden {
				www := strings.ToLower(headers.Get("Www-Authenticate"))
				return strings.Contains(bodyStr, "agent-card") || strings.Contains(bodyStr, "a2a") || strings.Contains(www, "a2a")
			}
			return false
		},
	}
}

// VLLMDefinition returns the fingerprint definition for vLLM inference servers.
// Generic OpenAI-compatible /v1/models responses without vLLM-specific evidence
// intentionally do not match.
func VLLMDefinition() Definition {
	return Definition{
		Surface:     SurfaceVLLM,
		DefaultPort: 8000,
		ProbePaths:  []string{"/v1/models", "/version"},
		Match: func(status int, headers http.Header, body []byte) bool {
			if strings.Contains(strings.ToLower(headers.Get("Server")), "vllm") {
				return true
			}
			bodyStr := strings.ToLower(string(body))
			if status == http.StatusOK {
				var models struct {
					Data []struct {
						OwnedBy     string `json:"owned_by"`
						MaxModelLen *int64 `json:"max_model_len"`
					} `json:"data"`
				}
				if json.Unmarshal(body, &models) == nil && models.Data != nil {
					for _, m := range models.Data {
						if strings.EqualFold(strings.TrimSpace(m.OwnedBy), "vllm") || m.MaxModelLen != nil {
							return true
						}
					}
					return false
				}
				var ver struct {
					Version string `json:"version"`
				}
				var doc map[string]json.RawMessage
				if json.Unmarshal(body, &doc) == nil && len(doc) == 1 && doc["version"] != nil &&
					json.Unmarshal(body, &ver) == nil && strings.TrimSpace(ver.Version) != "" {
					return true
				}
			}
			if status == http.StatusUnauthorized || status == http.StatusForbidden {
				return strings.Contains(bodyStr, "vllm") || strings.Contains(strings.ToLower(headers.Get("Www-Authenticate")), "vllm")
			}
			return false
		},
	}
}

// QdrantDefinition returns the fingerprint definition for Qdrant vector databases.
func QdrantDefinition() Definition {
	return Definition{
		Surface:     SurfaceQdrant,
		DefaultPort: 6333,
		ProbePaths:  []string{"/", "/collections"},
		Match: func(status int, headers http.Header, body []byte) bool {
			if strings.Contains(strings.ToLower(headers.Get("Server")), "qdrant") {
				return true
			}
			bodyStr := strings.ToLower(string(body))
			if status == http.StatusOK {
				var root struct {
					Title string `json:"title"`
				}
				if json.Unmarshal(body, &root) == nil && strings.Contains(strings.ToLower(root.Title), "qdrant") {
					return true
				}
				var cols struct {
					Result *struct {
						Collections []json.RawMessage `json:"collections"`
					} `json:"result"`
				}
				if json.Unmarshal(body, &cols) == nil && cols.Result != nil && cols.Result.Collections != nil {
					return true
				}
			}
			if status == http.StatusUnauthorized || status == http.StatusForbidden {
				return strings.Contains(bodyStr, "qdrant") || strings.Contains(strings.ToLower(headers.Get("Www-Authenticate")), "qdrant")
			}
			return false
		},
	}
}

// LiteLLMDefinition returns the fingerprint definition for LiteLLM proxy gateways.
func LiteLLMDefinition() Definition {
	return Definition{
		Surface:     SurfaceLiteLLM,
		DefaultPort: 4000,
		ProbePaths:  []string{"/openapi.json", "/model/info", "/v1/models"},
		Match: func(status int, headers http.Header, body []byte) bool {
			for k := range headers {
				if strings.HasPrefix(strings.ToLower(k), "x-litellm-") {
					return true
				}
			}
			if strings.Contains(strings.ToLower(headers.Get("Server")), "litellm") {
				return true
			}
			bodyStr := strings.ToLower(string(body))
			if status == http.StatusOK {
				var doc struct {
					Info struct {
						Title string `json:"title"`
					} `json:"info"`
					Paths map[string]json.RawMessage `json:"paths"`
				}
				if json.Unmarshal(body, &doc) == nil {
					if strings.Contains(strings.ToLower(doc.Info.Title), "litellm") {
						return true
					}
					if _, hasModels := doc.Paths["/v1/models"]; hasModels {
						for _, marker := range []string{"/model/info", "/key/generate", "/spend/logs"} {
							if _, ok := doc.Paths[marker]; ok {
								return true
							}
						}
					}
				}
				var mInfo struct {
					Data []struct {
						LiteLLMParams *struct {
							Model             string `json:"model"`
							APIBase           string `json:"api_base"`
							CustomLLMProvider string `json:"custom_llm_provider"`
						} `json:"litellm_params"`
						ModelInfo *struct {
							LiteLLMProvider string `json:"litellm_provider"`
						} `json:"model_info"`
					} `json:"data"`
				}
				if json.Unmarshal(body, &mInfo) == nil {
					for _, e := range mInfo.Data {
						if (e.LiteLLMParams != nil && (e.LiteLLMParams.Model != "" || e.LiteLLMParams.APIBase != "" || e.LiteLLMParams.CustomLLMProvider != "")) ||
							(e.ModelInfo != nil && e.ModelInfo.LiteLLMProvider != "") {
							return true
						}
					}
				}
			}
			if status == http.StatusUnauthorized || status == http.StatusForbidden {
				return strings.Contains(bodyStr, "litellm") || strings.Contains(strings.ToLower(headers.Get("Www-Authenticate")), "litellm")
			}
			return false
		},
	}
}

// MLflowDefinition returns the fingerprint definition for MLflow tracking servers.
func MLflowDefinition() Definition {
	return Definition{
		Surface:     SurfaceMLflow,
		DefaultPort: 5000,
		ProbePaths:  []string{"/api/2.0/mlflow/experiments/search?max_results=1", "/api/2.0/mlflow/registered-models/search?max_results=1"},
		Match: func(status int, headers http.Header, body []byte) bool {
			if strings.Contains(strings.ToLower(headers.Get("Server")), "mlflow") {
				return true
			}
			bodyStr := strings.ToLower(string(body))
			if status == http.StatusOK {
				var doc map[string]json.RawMessage
				if json.Unmarshal(body, &doc) == nil {
					if raw, ok := doc["experiments"]; ok && strings.HasPrefix(strings.TrimSpace(string(raw)), "[") {
						return true
					}
					if raw, ok := doc["registered_models"]; ok && strings.HasPrefix(strings.TrimSpace(string(raw)), "[") {
						return true
					}
				}
			}
			if status == http.StatusUnauthorized || status == http.StatusForbidden {
				return strings.Contains(bodyStr, "mlflow") || strings.Contains(strings.ToLower(headers.Get("Www-Authenticate")), "mlflow")
			}
			return false
		},
	}
}

// OpenWebUIDefinition returns the fingerprint definition for Open WebUI instances.
func OpenWebUIDefinition() Definition {
	return Definition{
		Surface:     SurfaceOpenWebUI,
		DefaultPort: 3000,
		ProbePaths:  []string{"/api/config"},
		Match: func(status int, headers http.Header, body []byte) bool {
			srv := strings.ToLower(headers.Get("Server"))
			if strings.Contains(srv, "open-webui") || strings.Contains(srv, "open webui") {
				return true
			}
			bodyStr := strings.ToLower(string(body))
			if status == http.StatusOK {
				var doc struct {
					Status            *bool           `json:"status"`
					Name              string          `json:"name"`
					Onboarding        json.RawMessage `json:"onboarding"`
					DefaultModels     json.RawMessage `json:"default_models"`
					OllamaBaseURLs    []string        `json:"ollama_base_urls"`
					OpenAIAPIBaseURLs []string        `json:"openai_api_base_urls"`
					Features          *struct {
						Auth         *bool `json:"auth"`
						EnableSignup *bool `json:"enable_signup"`
					} `json:"features"`
				}
				if json.Unmarshal(body, &doc) == nil {
					if strings.Contains(strings.ToLower(doc.Name), "open webui") {
						return true
					}
					if doc.Features != nil && (doc.Features.Auth != nil || doc.Features.EnableSignup != nil) {
						return true
					}
					if len(doc.Onboarding) > 0 || (len(doc.DefaultModels) > 0 && doc.Status != nil) ||
						len(doc.OllamaBaseURLs) > 0 || len(doc.OpenAIAPIBaseURLs) > 0 {
						return true
					}
				}
			}
			if status == http.StatusUnauthorized || status == http.StatusForbidden {
				return strings.Contains(bodyStr, "open webui") || strings.Contains(bodyStr, "open-webui") || strings.Contains(strings.ToLower(headers.Get("Www-Authenticate")), "open-webui")
			}
			return false
		},
	}
}

// LangServeDefinition returns the fingerprint definition for LangServe applications.
func LangServeDefinition() Definition {
	return Definition{
		Surface:     SurfaceLangServe,
		DefaultPort: 8000,
		ProbePaths:  []string{"/openapi.json"},
		Match: func(status int, headers http.Header, body []byte) bool {
			if headers.Get("X-LangServe-Version") != "" || headers.Get("X-Langserve-Version") != "" {
				return true
			}
			bodyStr := strings.ToLower(string(body))
			if status == http.StatusOK {
				var doc struct {
					Info struct {
						Title             string `json:"title"`
						Description       string `json:"description"`
						XLangServeVersion string `json:"x-langserve-version"`
					} `json:"info"`
					Paths map[string]json.RawMessage `json:"paths"`
				}
				if json.Unmarshal(body, &doc) == nil {
					if strings.Contains(strings.ToLower(doc.Info.Title), "langserve") ||
						strings.Contains(strings.ToLower(doc.Info.Description), "langserve") ||
						doc.Info.XLangServeVersion != "" {
						return true
					}
					byBase := make(map[string]map[string]bool)
					suffixes := []string{"/invoke", "/batch", "/stream", "/stream_log", "/stream_events", "/input_schema", "/output_schema", "/config_schema", "/playground"}
					for p := range doc.Paths {
						clean := strings.TrimRight(p, "/")
						for _, suf := range suffixes {
							if strings.HasSuffix(clean, suf) {
								base := strings.TrimSuffix(clean, suf)
								if byBase[base] == nil {
									byBase[base] = make(map[string]bool)
								}
								byBase[base][suf] = true
								break
							}
						}
					}
					for _, seen := range byBase {
						hasInvoke := seen["/invoke"] || seen["/batch"] || seen["/stream"] || seen["/stream_log"] || seen["/stream_events"]
						hasSchema := seen["/input_schema"] || seen["/output_schema"] || seen["/config_schema"] || seen["/playground"]
						if (hasInvoke && hasSchema) || len(seen) >= 3 {
							return true
						}
					}
				}
			}
			if status == http.StatusUnauthorized || status == http.StatusForbidden {
				return strings.Contains(bodyStr, "langserve") || strings.Contains(strings.ToLower(headers.Get("Www-Authenticate")), "langserve")
			}
			return false
		},
	}
}

// RayDefinition returns the fingerprint definition for Ray Dashboard endpoints.
func RayDefinition() Definition {
	return Definition{
		Surface:     SurfaceRay,
		DefaultPort: 8265,
		ProbePaths:  []string{"/api/version", "/api/cluster_status", "/api/jobs/"},
		Match: func(status int, headers http.Header, body []byte) bool {
			bodyStr := strings.ToLower(string(body))
			if status == http.StatusOK {
				var ver struct {
					RayVersion string `json:"ray_version"`
					RayCommit  string `json:"ray_commit"`
				}
				if json.Unmarshal(body, &ver) == nil && (strings.TrimSpace(ver.RayVersion) != "" || strings.TrimSpace(ver.RayCommit) != "") {
					return true
				}
				var cs struct {
					Result bool `json:"result"`
					Data   struct {
						ClusterStatus     json.RawMessage `json:"clusterStatus"`
						LoadMetricsReport json.RawMessage `json:"loadMetricsReport"`
					} `json:"data"`
				}
				if json.Unmarshal(body, &cs) == nil && cs.Result && (len(cs.Data.ClusterStatus) > 0 || len(cs.Data.LoadMetricsReport) > 0) {
					return true
				}
				var jobs []struct {
					SubmissionID string `json:"submission_id"`
				}
				if json.Unmarshal(body, &jobs) == nil {
					for _, j := range jobs {
						if j.SubmissionID != "" {
							return true
						}
					}
				}
			}
			if status == http.StatusUnauthorized || status == http.StatusForbidden {
				return strings.Contains(bodyStr, "ray") || strings.Contains(strings.ToLower(headers.Get("Www-Authenticate")), "ray")
			}
			return false
		},
	}
}

// LangflowDefinition returns the fingerprint definition for Langflow endpoints.
func LangflowDefinition() Definition {
	return Definition{
		Surface:     SurfaceLangflow,
		DefaultPort: 7860,
		ProbePaths:  []string{"/api/v1/version", "/api/v1/auto_login"},
		Match: func(status int, headers http.Header, body []byte) bool {
			bodyStr := strings.ToLower(string(body))
			if status == http.StatusOK {
				var ver struct {
					Version     string `json:"version"`
					MainVersion string `json:"main_version"`
					Package     string `json:"package"`
				}
				if json.Unmarshal(body, &ver) == nil {
					if strings.Contains(strings.ToLower(ver.Package), "langflow") ||
						(strings.TrimSpace(ver.MainVersion) != "" && strings.TrimSpace(ver.Version) != "") {
						return true
					}
				}
				var al struct {
					TokenType string `json:"token_type"`
					AutoLogin *bool  `json:"auto_login"`
				}
				if json.Unmarshal(body, &al) == nil && (strings.TrimSpace(al.TokenType) != "" || al.AutoLogin != nil) {
					return true
				}
			}
			if status == http.StatusUnauthorized || status == http.StatusForbidden {
				return strings.Contains(bodyStr, "langflow") || strings.Contains(strings.ToLower(headers.Get("Www-Authenticate")), "langflow")
			}
			return false
		},
	}
}

// FlowiseDefinition returns the fingerprint definition for Flowise endpoints.
func FlowiseDefinition() Definition {
	return Definition{
		Surface:     SurfaceFlowise,
		DefaultPort: 3000,
		ProbePaths:  []string{"/api/v1/chatflows", "/api/v1/version"},
		Match: func(status int, headers http.Header, body []byte) bool {
			if strings.Contains(strings.ToLower(headers.Get("Server")), "flowise") {
				return true
			}
			bodyStr := strings.ToLower(string(body))
			if status == http.StatusOK {
				var flows []struct {
					FlowData string `json:"flowData"`
					IsPublic *bool  `json:"isPublic"`
					Deployed *bool  `json:"deployed"`
				}
				if json.Unmarshal(body, &flows) == nil {
					for _, f := range flows {
						if f.FlowData != "" || f.IsPublic != nil || f.Deployed != nil {
							return true
						}
					}
				}
				var ver struct {
					Version     string `json:"version"`
					Package     string `json:"package"`
					MainVersion string `json:"main_version"`
				}
				var doc map[string]json.RawMessage
				if json.Unmarshal(body, &doc) == nil && len(doc) == 1 && doc["version"] != nil &&
					json.Unmarshal(body, &ver) == nil && strings.TrimSpace(ver.Version) != "" &&
					ver.Package == "" && ver.MainVersion == "" {
					return true
				}
			}
			if status == http.StatusUnauthorized || status == http.StatusForbidden {
				return strings.Contains(bodyStr, "flowise") || strings.Contains(strings.ToLower(headers.Get("Www-Authenticate")), "flowise")
			}
			return false
		},
	}
}

// ChromaDBDefinition returns the fingerprint definition for ChromaDB endpoints.
func ChromaDBDefinition() Definition {
	return Definition{
		Surface:     SurfaceChromaDB,
		DefaultPort: 8000,
		ProbePaths:  []string{"/api/v2/heartbeat", "/api/v1/heartbeat"},
		Match: func(status int, headers http.Header, body []byte) bool {
			bodyStr := strings.ToLower(string(body))
			if status == http.StatusOK {
				var doc map[string]any
				if json.Unmarshal(body, &doc) == nil {
					if _, ok := doc["nanosecond heartbeat"]; ok {
						return true
					}
				}
			}
			if status == http.StatusUnauthorized || status == http.StatusForbidden {
				return strings.Contains(bodyStr, "chroma") || strings.Contains(strings.ToLower(headers.Get("Www-Authenticate")), "chroma")
			}
			return false
		},
	}
}

// OpenAICompatibleDefinition returns the generic fallback fingerprint definition
// for OpenAI-compatible /v1/models endpoints when no specific product is proven.
func OpenAICompatibleDefinition() Definition {
	return Definition{
		Surface:     SurfaceOpenAICompatible,
		DefaultPort: 8000,
		ProbePaths:  []string{"/v1/models"},
		Match: func(status int, headers http.Header, body []byte) bool {
			srv := strings.ToLower(headers.Get("Server"))
			if strings.Contains(srv, "vllm") || strings.Contains(srv, "litellm") || strings.Contains(srv, "ollama") {
				return false
			}
			for k := range headers {
				if strings.HasPrefix(strings.ToLower(k), "x-litellm-") {
					return false
				}
			}
			if status == http.StatusOK {
				var models struct {
					Object string `json:"object"`
					Data   []struct {
						ID          string `json:"id"`
						OwnedBy     string `json:"owned_by"`
						MaxModelLen *int64 `json:"max_model_len"`
					} `json:"data"`
				}
				if json.Unmarshal(body, &models) == nil && models.Object == "list" && models.Data != nil {
					for _, m := range models.Data {
						if strings.EqualFold(strings.TrimSpace(m.OwnedBy), "vllm") || m.MaxModelLen != nil {
							return false
						}
					}
					return true
				}
			}
			return false
		},
	}
}

// ProbeResult holds the result of probing a target against a fingerprint definition.
type ProbeResult struct {
	Matched     bool
	Surface     Surface
	MatchedPath string
	StatusCode  int
	Latency     time.Duration
	Reachable   bool
	Reason      string
}

// Probe executes fingerprint probing for a target URL against a definition.
func Probe(ctx context.Context, client *http.Client, baseURL string, def Definition) (ProbeResult, error) {
	baseURL = strings.TrimRight(baseURL, "/")
	probeClient := http.DefaultClient
	if client != nil {
		copyClient := *client
		copyClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
		probeClient = &copyClient
	} else {
		probeClient = &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}

	reachable := false
	for _, p := range def.ProbePaths {
		targetURL := baseURL + p
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
		if err != nil {
			return ProbeResult{}, fmt.Errorf("create probe request: %w", err)
		}
		req.Header.Set("Accept", "application/json, text/html;q=0.9, */*;q=0.8")

		start := time.Now()
		resp, err := probeClient.Do(req)
		latency := time.Since(start)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ProbeResult{}, ctxErr
			}
			continue
		}

		reachable = true
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		_ = resp.Body.Close()

		if def.Match != nil && def.Match(resp.StatusCode, resp.Header, body) {
			return ProbeResult{
				Matched:     true,
				Surface:     def.Surface,
				MatchedPath: p,
				StatusCode:  resp.StatusCode,
				Latency:     latency,
				Reachable:   true,
			}, nil
		}
	}

	reason := "no " + string(def.Surface) + "-specific evidence on probed paths"
	if !reachable {
		reason = "target unreachable on all probed paths"
	}
	return ProbeResult{
		Matched:   false,
		Surface:   def.Surface,
		Reachable: reachable,
		Reason:    reason,
	}, nil
}

// DefinitionFileEntry represents a single fingerprint definition in JSON/YAML.
type DefinitionFileEntry struct {
	Surface     string   `json:"surface"`
	DefaultPort int      `json:"default_port"`
	ProbePaths  []string `json:"probe_paths"`
}

// LoadDefinitions parses custom definitions from JSON data. Builtin match functions
// are associated with recognized surface names.
func LoadDefinitions(data []byte) ([]Definition, error) {
	var entries []DefinitionFileEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("decode definitions: %w", err)
	}
	if len(entries) == 0 {
		return nil, errors.New("definitions file contains no entries")
	}

	var out []Definition
	for _, e := range entries {
		s := Surface(strings.ToLower(strings.TrimSpace(e.Surface)))
		if s == "" {
			return nil, errors.New("definition missing surface")
		}
		port := e.DefaultPort
		if port <= 0 || port > 65535 {
			return nil, fmt.Errorf("surface %s has invalid default_port %d", s, port)
		}
		paths := e.ProbePaths
		if len(paths) == 0 {
			paths = []string{"/"}
		}

		// Inherit builtin matcher if available
		var match MatchFunc
		if builtin, ok := DefinitionForSurface(s); ok {
			match = builtin.Match
		} else {
			// Generic fallback matcher
			match = func(status int, headers http.Header, body []byte) bool {
				return status >= 200 && status < 300
			}
		}

		out = append(out, Definition{
			Surface:     s,
			DefaultPort: port,
			ProbePaths:  paths,
			Match:       match,
		})
	}
	return out, nil
}

// LoadDefinitionsFile reads and parses a fingerprint definitions JSON file.
func LoadDefinitionsFile(path string) ([]Definition, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read definitions file: %w", err)
	}
	return LoadDefinitions(data)
}
