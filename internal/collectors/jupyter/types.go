package jupyter

// apiVersionResponse parses the response from GET /api.
type apiVersionResponse struct {
	Version              string `json:"version"`
	ServerVersion        string `json:"server_version,omitempty"`
	JupyterServerVersion string `json:"jupyter_server_version,omitempty"`
}

// statusResponse parses the response from GET /api/status.
type statusResponse struct {
	Started      string `json:"started,omitempty"`
	LastActivity string `json:"last_activity,omitempty"`
	Kernels      int    `json:"kernels,omitempty"`
	Connections  int    `json:"connections,omitempty"`
}

// sessionResponse parses elements from GET /api/sessions.
type sessionResponse struct {
	ID     string          `json:"id"`
	Path   string          `json:"path"`
	Name   string          `json:"name"`
	Type   string          `json:"type"`
	Kernel *kernelResponse `json:"kernel,omitempty"`
}

// kernelResponse parses kernel metadata within a session.
type kernelResponse struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	ExecutionState string `json:"execution_state,omitempty"`
	Connections    int    `json:"connections,omitempty"`
	LastActivity   string `json:"last_activity,omitempty"`
}

// contentsResponse parses the directory response from GET /api/contents.
type contentsResponse struct {
	Name         string         `json:"name"`
	Path         string         `json:"path"`
	Type         string         `json:"type"`
	Created      string         `json:"created,omitempty"`
	LastModified string         `json:"last_modified,omitempty"`
	Size         *int64         `json:"size,omitempty"`
	Content      []contentsItem `json:"content,omitempty"`
}

// contentsItem parses metadata for an item listed in a directory.
// File contents/bodies are NEVER parsed or requested.
type contentsItem struct {
	Name         string `json:"name"`
	Path         string `json:"path"`
	Type         string `json:"type"` // "notebook", "file", "directory"
	Created      string `json:"created,omitempty"`
	LastModified string `json:"last_modified,omitempty"`
	Size         *int64 `json:"size,omitempty"`
}

// CollectedFile represents a notebook or file metadata item discovered in the workspace.
type CollectedFile struct {
	Name         string
	Path         string
	Type         string
	Size         int64
	LastModified string
}

// CollectedSession represents active session metadata discovered on the server.
type CollectedSession struct {
	ID          string
	Path        string
	Name        string
	Type        string
	KernelName  string
	KernelState string
}

// VersionInfo holds discovered API and server versions.
type VersionInfo struct {
	APIVersion      string
	SoftwareVersion string
	Details         map[string]any
}

// TLSInfo holds TLS handshake and certificate metadata observed during requests.
type TLSInfo struct {
	Observed           bool
	Fingerprint        string
	Issuer             string
	Subject            string
	SANs               []string
	ValidFrom          string
	ValidTo            string
	VerificationResult string
	VerificationReason string
	NegotiatedVersion  string
	InsecureOverride   bool
}

// CheckIDs defines stable identifiers for Jupyter collector allowlisted checks.
const (
	CheckIDVersion  = "jupyter_version"
	CheckIDSessions = "jupyter_sessions"
	CheckIDContents = "jupyter_contents"

	OpVersion  = "jupyter_api_version"
	OpSessions = "jupyter_sessions"
	OpContents = "jupyter_contents_list"
)
