// Package config loads and validates the operator's collection policy.
// It does not contact targets, resolve DNS, or perform correlation.
package config

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
	"unicode"

	extrules "github.com/0x3df/LLMHound/extension/rules"
	"github.com/0x3df/LLMHound/internal/graph"
	"github.com/0x3df/LLMHound/internal/targets"
	"gopkg.in/yaml.v3"
)

const MaxConfigBytes = 64 << 10

const (
	DefaultContentMaxItemBytes        int64 = 256 << 10 // 256 KiB
	DefaultContentMaxItemsPerResource int   = 10
	DefaultContentMaxServiceBytes     int64 = 5 << 20 // 5 MiB
	DefaultContentMaxSamplePoints     int   = 5

	HardMaxContentItemBytes        int64 = 16 << 20 // 16 MiB
	HardMaxContentItemsPerResource int   = 1000
	HardMaxContentServiceBytes     int64 = 256 << 20 // 256 MiB
	HardMaxContentSamplePoints     int   = 1000
)

// Optimal scan profile, graph mode, URL scheme, and content mode constants.
const (
	ProfileAttackPath = "attack-path"
	ProfileRCEOnly    = "rce-only"
	ProfileFull       = "full"

	GraphModeAttackPath = "attack-path"
	GraphModeFull       = "full"

	SchemeAuto  = "auto"
	SchemeHTTP  = "http"
	SchemeHTTPS = "https"

	ContentModeSecretsOnly = "secrets-only"
	ContentModeMetadata    = "metadata"
	ContentModeFull        = "full"
)

type Config struct {
	Scope             string            `yaml:"scope"`
	VantageKey        string            `yaml:"vantage_key"`
	Targets           []string          `yaml:"targets"`
	CIDRs             []string          `yaml:"cidrs"`
	TargetsFiles      []string          `yaml:"targets_files"`
	EndpointsFiles    []string          `yaml:"endpoints_files"`
	Exclude           []string          `yaml:"exclude"`
	ExcludeFiles      []string          `yaml:"exclude_files"`
	Bounds            Bounds            `yaml:"bounds"`
	Scan              ScanPolicy        `yaml:"scan"`
	Insecure          bool              `yaml:"insecure"`
	UserAgent         string            `yaml:"user_agent"`
	Content           Content           `yaml:"content"`
	Secrets           Secrets           `yaml:"secrets"`
	Correlation       Correlation       `yaml:"correlation"`
	PathQualification PathQualification `yaml:"path_qualification"`
}

// ScanPolicy controls discovery profile, transport scheme, checkpoint density,
// and BloodHound graph emission granularity.
type ScanPolicy struct {
	Profile           string   `yaml:"profile"`
	Surfaces          []string `yaml:"surfaces"`
	GraphMode         string   `yaml:"graph_mode"`
	Scheme            string   `yaml:"scheme"`
	RecordUnmatched   bool     `yaml:"record_unmatched"`
	CompactJSON       bool     `yaml:"compact_json"`
	MappedOnly        bool     `yaml:"mapped_only"`
	MappedOnlyTargets bool     `yaml:"mapped_only_targets"`
	ExtraPorts        []int    `yaml:"extra_ports"`
}

// ReachPrincipal identifies an existing BloodHound native principal (e.g.
// Domain Users Group) from which enabled path-qualification rules emit
// CanExecuteOn edges.
type ReachPrincipal struct {
	ObjectID string `yaml:"object_id"`
	Kind     string `yaml:"kind"`
}

// EffectiveKind returns the principal's native kind, defaulting to Group when omitted.
func (p ReachPrincipal) EffectiveKind() graph.Kind {
	k := strings.TrimSpace(p.Kind)
	if k == "" {
		return graph.Kind("Group")
	}
	return graph.Kind(k)
}

// PathQualification configures opt-in, rule-gated traversable
// edges (M2d). Rules ship disabled and require explicit operator opt-in plus
// assumed_reach_principals and/or vantage_principals.
type PathQualification struct {
	EnabledRules           []string                    `yaml:"enabled_rules"`
	AssumedReachPrincipals []ReachPrincipal            `yaml:"assumed_reach_principals"`
	VantagePrincipals      map[string][]ReachPrincipal `yaml:"vantage_principals"`
}

var knownRuleIDs = loadKnownRuleIDs()

func loadKnownRuleIDs() map[string]bool {
	out := make(map[string]bool)
	entries, err := fs.ReadDir(extrules.FS, ".")
	if err != nil {
		return out
	}
	for _, ent := range entries {
		data, err := fs.ReadFile(extrules.FS, ent.Name())
		if err != nil {
			continue
		}
		var hdr struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(data, &hdr) == nil && hdr.ID != "" {
			out[hdr.ID] = true
		}
	}
	return out
}

// IsKnownPathRule reports whether id names a shipped path-qualification rule.
func IsKnownPathRule(id string) bool {
	return knownRuleIDs[id]
}

// Secrets controls high-precision secret detectors run over content-tier
// bodies. Every detector is enabled unless explicitly set to false.
type Secrets struct {
	Detectors map[string]bool `yaml:"detectors"`
}

// SecretDetectorNames is the closed list of detector names (sorted).
var SecretDetectorNames = []string{"aws_access_key", "azure_client_secret", "github_token", "private_key"}

// IsKnownSecretDetector reports whether name is one of the built-in detectors.
func IsKnownSecretDetector(name string) bool {
	for _, known := range SecretDetectorNames {
		if known == name {
			return true
		}
	}
	return false
}

// DetectorEnabled reports whether the named detector should run. A missing key
// means enabled; only an explicit false disables it.
func (s Secrets) DetectorEnabled(name string) bool {
	if v, ok := s.Detectors[name]; ok {
		return v
	}
	return true
}

type Bounds struct {
	Concurrency      int           `yaml:"concurrency"`
	TCPConcurrency   int           `yaml:"tcp_concurrency"`
	TCPTimeout       time.Duration `yaml:"tcp_timeout"`
	PerHostRate      float64       `yaml:"per_host_rate"`
	ConnectTimeout   time.Duration `yaml:"connect_timeout"`
	ResponseTimeout  time.Duration `yaml:"response_timeout"`
	MaxResponseBytes int64         `yaml:"max_response_bytes"`
	MaxPages         int           `yaml:"max_pages"`
	MaxItems         int           `yaml:"max_items"`
	MaxRedirects     int           `yaml:"max_redirects"`
	MaxTargets       int           `yaml:"max_targets"`
}

// Content controls bounded, anonymous, read-only collection of existing service
// content (system prompts, modelfiles, configuration, workspace files, MCP
// resource bodies, flow definitions, and bounded samples).
type Content struct {
	Enabled             bool            `yaml:"enabled"`
	Mode                string          `yaml:"mode"`
	MaxItemBytes        int64           `yaml:"max_item_bytes"`
	MaxItemsPerResource int             `yaml:"max_items_per_resource"`
	MaxServiceBytes     int64           `yaml:"max_service_bytes"`
	MaxSamplePoints     int             `yaml:"max_sample_points"`
	Surfaces            map[string]bool `yaml:"surfaces"`
}

// HighYieldSecretSurfaces returns the surfaces scanned for exposed secrets by
// default in secrets-only content mode.
func HighYieldSecretSurfaces() map[string]bool {
	return map[string]bool{
		"jupyter":    true,
		"litellm":    true,
		"langflow":   true,
		"flowise":    true,
		"ray":        true,
		"open_webui": true,
	}
}

// DefaultContent returns the default content-tier policy: in-memory secrets-only
// scanning on high-yield surfaces with zero .content.jsonl disk bloat.
func DefaultContent() Content {
	return Content{
		Enabled:             true,
		Mode:                ContentModeSecretsOnly,
		MaxItemBytes:        DefaultContentMaxItemBytes,
		MaxItemsPerResource: DefaultContentMaxItemsPerResource,
		MaxServiceBytes:     DefaultContentMaxServiceBytes,
		MaxSamplePoints:     DefaultContentMaxSamplePoints,
	}
}

// EnabledFor reports whether content-tier reads are enabled for surface.
func (c Content) EnabledFor(surface string) bool {
	if !c.Enabled {
		return false
	}
	mode := strings.ToLower(strings.TrimSpace(c.Mode))
	if mode == ContentModeMetadata {
		return false
	}
	norm := strings.ToLower(strings.TrimSpace(surface))
	if len(c.Surfaces) > 0 {
		if v, ok := c.Surfaces[norm]; ok {
			return v
		}
	}
	if mode == ContentModeSecretsOnly {
		return HighYieldSecretSurfaces()[norm]
	}
	return true
}

// IsKnownContentSurface reports whether name is a canonical capability-matrix surface key.
func IsKnownContentSurface(name string) bool {
	switch name {
	case "ollama", "jupyter", "mcp",
		"a2a", "vllm", "litellm", "qdrant", "mlflow", "open_webui", "langserve",
		"openai_compatible", "ray", "langflow", "flowise", "chromadb":
		return true
	}
	return false
}

// Correlation holds policy only; this package never reads mappings or looks up
// hosts. Attribution is the normalization program's job: it supplies an asset
// mapping (target to existing BloodHound objectid and node kind) and LLMHound
// attaches services to exactly what that mapping asserts.
type Correlation struct {
	MappingFile string `yaml:"mapping_file"`
}

func Defaults() Config {
	return Config{
		Bounds: Bounds{
			Concurrency:      64,
			TCPConcurrency:   512,
			TCPTimeout:       750 * time.Millisecond,
			PerHostRate:      5,
			ConnectTimeout:   3 * time.Second,
			ResponseTimeout:  10 * time.Second,
			MaxResponseBytes: 1 << 20,
			MaxPages:         100,
			MaxItems:         10000,
			MaxRedirects:     0,
			MaxTargets:       65536,
		},
		Scan: ScanPolicy{
			Profile:         ProfileAttackPath,
			GraphMode:       GraphModeAttackPath,
			Scheme:          SchemeAuto,
			RecordUnmatched: false,
			CompactJSON:     true,
		},
		UserAgent: "LLMHound/dev",
		Content:   DefaultContent(),
	}
}

// Load overlays a single strict YAML document on defaults. Required fields are
// validated later, after explicit flag replacements. Paths in the file are
// relative to its directory, not to the process working directory.
func Load(path string) (Config, error) {
	info, err := os.Stat(path)
	if err != nil {
		return Config{}, fmt.Errorf("stat config: %w", err)
	}
	if !info.Mode().IsRegular() {
		return Config{}, fmt.Errorf("config must be a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open config: %w", err)
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxConfigBytes+1))
	closeErr := f.Close()
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	if closeErr != nil {
		return Config{}, fmt.Errorf("close config: %w", closeErr)
	}
	if len(data) > MaxConfigBytes {
		return Config{}, fmt.Errorf("config exceeds %d byte limit", MaxConfigBytes)
	}
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	var node yaml.Node
	if err := dec.Decode(&node); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	if len(node.Content) != 1 || node.Content[0].Kind != yaml.MappingNode {
		return Config{}, fmt.Errorf("config must be a YAML mapping")
	}
	if err := strictNodes(&node); err != nil {
		return Config{}, err
	}
	if err := strictTypes(node.Content[0], reflect.TypeOf(Config{})); err != nil {
		return Config{}, err
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err != io.EOF {
		return Config{}, fmt.Errorf("config must contain exactly one YAML document")
	}
	c := Defaults()
	dec = yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return Config{}, fmt.Errorf("config path: %w", err)
	}
	dir := filepath.Dir(abs)
	relative := func(p string) string {
		if strings.TrimSpace(p) != "" && !filepath.IsAbs(p) {
			return filepath.Join(dir, p)
		}
		return p
	}
	for i, p := range c.TargetsFiles {
		c.TargetsFiles[i] = relative(p)
	}
	for i, p := range c.EndpointsFiles {
		c.EndpointsFiles[i] = relative(p)
	}
	for i, p := range c.ExcludeFiles {
		c.ExcludeFiles[i] = relative(p)
	}
	c.Correlation.MappingFile = relative(c.Correlation.MappingFile)
	return c, nil
}

func strictNodes(n *yaml.Node) error {
	if n.Kind == yaml.AliasNode || n.Anchor != "" || n.Tag == "!!merge" {
		return fmt.Errorf("config aliases, anchors, and merge keys are not supported (line %d)", n.Line)
	}
	if n.Tag == "!!null" {
		return fmt.Errorf("config null values are not supported (line %d)", n.Line)
	}
	if n.Kind == yaml.MappingNode {
		for i := 0; i < len(n.Content); i += 2 {
			if n.Content[i].Tag != "!!str" {
				return fmt.Errorf("config keys must be strings (line %d)", n.Content[i].Line)
			}
		}
	}
	for _, child := range n.Content {
		if err := strictNodes(child); err != nil {
			return err
		}
	}
	return nil
}

// strictTypes prevents YAML's implicit string/bool/integer coercions from
// silently changing an operator's policy (for example truncating 1.5 to 1).
func strictTypes(n *yaml.Node, typ reflect.Type) error {
	if typ == reflect.TypeOf(time.Duration(0)) {
		if n.Kind == yaml.ScalarNode && n.Tag == "!!str" {
			return nil
		}
		return fmt.Errorf("config duration must be a string with units (line %d)", n.Line)
	}
	switch typ.Kind() {
	case reflect.Struct:
		if n.Kind != yaml.MappingNode {
			break
		}
		fields := make(map[string]reflect.Type)
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			fields[f.Tag.Get("yaml")] = f.Type
		}
		for i := 0; i < len(n.Content); i += 2 {
			if field, ok := fields[n.Content[i].Value]; ok {
				if err := strictTypes(n.Content[i+1], field); err != nil {
					return err
				}
			}
		}
		return nil
	case reflect.Slice:
		if n.Kind != yaml.SequenceNode {
			break
		}
		for _, child := range n.Content {
			if err := strictTypes(child, typ.Elem()); err != nil {
				return err
			}
		}
		return nil
	case reflect.Map:
		if n.Kind != yaml.MappingNode {
			break
		}
		if typ.Key().Kind() != reflect.String {
			return fmt.Errorf("invalid config map key type %s (line %d)", typ.Key(), n.Line)
		}
		for i := 0; i < len(n.Content); i += 2 {
			if err := strictTypes(n.Content[i+1], typ.Elem()); err != nil {
				return err
			}
		}
		return nil
	case reflect.String:
		if n.Kind == yaml.ScalarNode && n.Tag == "!!str" {
			return nil
		}
	case reflect.Bool:
		if n.Kind == yaml.ScalarNode && n.Tag == "!!bool" {
			return nil
		}
	case reflect.Int, reflect.Int64:
		if n.Kind == yaml.ScalarNode && n.Tag == "!!int" {
			return nil
		}
	case reflect.Float64:
		if n.Kind == yaml.ScalarNode && (n.Tag == "!!float" || n.Tag == "!!int") {
			return nil
		}
	}
	return fmt.Errorf("invalid config type for %s (line %d)", typ, n.Line)
}

// Apply replaces only named, explicitly provided flag fields. Lists replace
// their own field rather than appending or clearing unrelated target sources.
func Apply(c, flags Config, fields []string) (Config, error) {
	for _, field := range fields {
		switch field {
		case "scope":
			c.Scope = flags.Scope
		case "vantage":
			c.VantageKey = flags.VantageKey
		case "targets":
			c.Targets = flags.Targets
		case "cidr":
			c.CIDRs = flags.CIDRs
		case "targets-file":
			c.TargetsFiles = flags.TargetsFiles
		case "endpoints-file":
			c.EndpointsFiles = flags.EndpointsFiles
		case "exclude":
			c.Exclude = flags.Exclude
		case "exclude-file":
			c.ExcludeFiles = flags.ExcludeFiles
		case "concurrency":
			c.Bounds.Concurrency = flags.Bounds.Concurrency
		case "tcp-concurrency":
			c.Bounds.TCPConcurrency = flags.Bounds.TCPConcurrency
		case "tcp-timeout":
			c.Bounds.TCPTimeout = flags.Bounds.TCPTimeout
		case "per-host-rate":
			c.Bounds.PerHostRate = flags.Bounds.PerHostRate
		case "connect-timeout":
			c.Bounds.ConnectTimeout = flags.Bounds.ConnectTimeout
		case "response-timeout":
			c.Bounds.ResponseTimeout = flags.Bounds.ResponseTimeout
		case "max-response-bytes":
			c.Bounds.MaxResponseBytes = flags.Bounds.MaxResponseBytes
		case "max-pages":
			c.Bounds.MaxPages = flags.Bounds.MaxPages
		case "max-items":
			c.Bounds.MaxItems = flags.Bounds.MaxItems
		case "max-redirects":
			c.Bounds.MaxRedirects = flags.Bounds.MaxRedirects
		case "max-targets":
			c.Bounds.MaxTargets = flags.Bounds.MaxTargets
		case "profile":
			c.Scan.Profile = flags.Scan.Profile
		case "surfaces":
			c.Scan.Surfaces = flags.Scan.Surfaces
		case "graph-mode":
			c.Scan.GraphMode = flags.Scan.GraphMode
		case "scheme":
			c.Scan.Scheme = flags.Scan.Scheme
		case "record-unmatched":
			c.Scan.RecordUnmatched = flags.Scan.RecordUnmatched
		case "compact-json":
			c.Scan.CompactJSON = flags.Scan.CompactJSON
		case "mapped-only":
			c.Scan.MappedOnly = flags.Scan.MappedOnly
		case "mapped-only-targets":
			c.Scan.MappedOnlyTargets = flags.Scan.MappedOnlyTargets
		case "extra-ports":
			c.Scan.ExtraPorts = flags.Scan.ExtraPorts
		case "insecure":
			c.Insecure = flags.Insecure
		case "user-agent":
			c.UserAgent = flags.UserAgent
		case "content":
			c.Content.Enabled = flags.Content.Enabled
		case "content-mode":
			c.Content.Mode = flags.Content.Mode
		case "content-max-item-bytes":
			c.Content.MaxItemBytes = flags.Content.MaxItemBytes
		case "content-max-items-per-resource":
			c.Content.MaxItemsPerResource = flags.Content.MaxItemsPerResource
		case "content-max-service-bytes":
			c.Content.MaxServiceBytes = flags.Content.MaxServiceBytes
		case "content-max-sample-points":
			c.Content.MaxSamplePoints = flags.Content.MaxSamplePoints
		case "content-disable":
			if flags.Content.Surfaces == nil {
				c.Content.Surfaces = nil
			} else {
				cp := make(map[string]bool, len(flags.Content.Surfaces))
				for k, v := range flags.Content.Surfaces {
					cp[k] = v
				}
				c.Content.Surfaces = cp
			}
		case "mapping-file":
			c.Correlation.MappingFile = flags.Correlation.MappingFile
		default:
			return Config{}, fmt.Errorf("unknown override field %q", field)
		}
	}
	return c, nil
}

func (c Config) Validate() error {
	for _, key := range []struct{ name, value string }{{"scope", c.Scope}, {"vantage_key", c.VantageKey}} {
		name, value := key.name, key.value
		if value == "" || value != strings.TrimSpace(value) || len(value) > 128 || strings.ContainsFunc(value, unicode.IsControl) {
			return fmt.Errorf("%s is required and must be a stable nonblank key of at most 128 bytes without surrounding whitespace or control characters", name)
		}
	}
	if len(c.Targets)+len(c.CIDRs)+len(c.TargetsFiles)+len(c.EndpointsFiles) == 0 {
		return fmt.Errorf("at least one target, CIDR, targets file, or endpoints file is required")
	}
	if len(c.Targets)+len(c.CIDRs)+len(c.TargetsFiles)+len(c.EndpointsFiles)+len(c.Exclude)+len(c.ExcludeFiles) > targets.MaxInputEntries {
		return fmt.Errorf("too many target/exclusion input entries")
	}
	for _, value := range c.CIDRs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil || prefix.Addr().Is4In6() || prefix != prefix.Masked() {
			return fmt.Errorf("cidrs must contain canonical IP prefixes with no host bits")
		}
	}
	for name, list := range map[string][]string{"targets_files": c.TargetsFiles, "endpoints_files": c.EndpointsFiles, "exclude_files": c.ExcludeFiles} {
		for _, p := range list {
			if strings.TrimSpace(p) == "" || strings.ContainsFunc(p, unicode.IsControl) {
				return fmt.Errorf("%s contains an empty or invalid path", name)
			}
		}
	}
	if c.Correlation.MappingFile != "" && (strings.TrimSpace(c.Correlation.MappingFile) == "" || strings.ContainsFunc(c.Correlation.MappingFile, unicode.IsControl)) {
		return fmt.Errorf("correlation.mapping_file must be a nonblank path")
	}
	b := c.Bounds
	for _, limit := range []struct {
		name            string
		value, min, max int64
	}{
		{"concurrency", int64(b.Concurrency), 1, 1024},
		{"tcp_concurrency", int64(b.TCPConcurrency), 1, 4096},
		{"tcp_timeout", int64(b.TCPTimeout), int64(50 * time.Millisecond), int64(30 * time.Second)},
		{"connect_timeout", int64(b.ConnectTimeout), int64(time.Millisecond), int64(5 * time.Minute)},
		{"response_timeout", int64(b.ResponseTimeout), int64(time.Millisecond), int64(5 * time.Minute)},
		{"max_response_bytes", b.MaxResponseBytes, 1, 64 << 20},
		{"max_pages", int64(b.MaxPages), 1, 10000},
		{"max_items", int64(b.MaxItems), 1, 100000},
		{"max_redirects", int64(b.MaxRedirects), 0, 10},
		{"max_targets", int64(b.MaxTargets), 1, targets.HardMaxTargets},
	} {
		if limit.value < limit.min || limit.value > limit.max {
			return fmt.Errorf("bounds.%s must be between %d and %d", limit.name, limit.min, limit.max)
		}
	}
	switch strings.ToLower(strings.TrimSpace(c.Scan.Profile)) {
	case "", ProfileAttackPath, ProfileRCEOnly, ProfileFull:
	default:
		return fmt.Errorf("scan.profile %q must be one of %q, %q, or %q", c.Scan.Profile, ProfileAttackPath, ProfileRCEOnly, ProfileFull)
	}
	for _, surf := range c.Scan.Surfaces {
		if !IsKnownContentSurface(surf) {
			return fmt.Errorf("scan.surfaces contains unknown surface %q", surf)
		}
	}
	switch strings.ToLower(strings.TrimSpace(c.Scan.GraphMode)) {
	case "", GraphModeAttackPath, GraphModeFull:
	default:
		return fmt.Errorf("scan.graph_mode %q must be %q or %q", c.Scan.GraphMode, GraphModeAttackPath, GraphModeFull)
	}
	switch strings.ToLower(strings.TrimSpace(c.Scan.Scheme)) {
	case "", SchemeAuto, SchemeHTTP, SchemeHTTPS:
	default:
		return fmt.Errorf("scan.scheme %q must be %q, %q, or %q", c.Scan.Scheme, SchemeAuto, SchemeHTTP, SchemeHTTPS)
	}
	for _, port := range c.Scan.ExtraPorts {
		if port < 1 || port > 65535 {
			return fmt.Errorf("scan.extra_ports contains invalid port %d (must be 1-65535)", port)
		}
	}
	if c.Scan.MappedOnlyTargets && strings.TrimSpace(c.Correlation.MappingFile) == "" {
		return fmt.Errorf("scan.mapped_only_targets requires correlation.mapping_file")
	}
	switch strings.ToLower(strings.TrimSpace(c.Content.Mode)) {
	case "", ContentModeSecretsOnly, ContentModeMetadata, ContentModeFull:
	default:
		return fmt.Errorf("content.mode %q must be %q, %q, or %q", c.Content.Mode, ContentModeSecretsOnly, ContentModeMetadata, ContentModeFull)
	}
	if math.IsNaN(b.PerHostRate) || math.IsInf(b.PerHostRate, 0) || b.PerHostRate < 0.1 || b.PerHostRate > 1000 {
		return fmt.Errorf("bounds.per_host_rate must be finite and between 0.1 and 1000 requests/second")
	}
	if strings.TrimSpace(c.UserAgent) == "" || len(c.UserAgent) > 256 {
		return fmt.Errorf("user_agent must be nonblank and at most 256 bytes")
	}
	for _, ch := range c.UserAgent {
		if ch < 32 || ch > 126 {
			return fmt.Errorf("user_agent must contain printable ASCII without control characters")
		}
	}
	for _, limit := range []struct {
		name            string
		value, min, max int64
	}{
		{"max_item_bytes", c.Content.MaxItemBytes, 1, HardMaxContentItemBytes},
		{"max_items_per_resource", int64(c.Content.MaxItemsPerResource), 1, int64(HardMaxContentItemsPerResource)},
		{"max_service_bytes", c.Content.MaxServiceBytes, 1, HardMaxContentServiceBytes},
		{"max_sample_points", int64(c.Content.MaxSamplePoints), 1, int64(HardMaxContentSamplePoints)},
	} {
		if limit.value < limit.min || limit.value > limit.max {
			return fmt.Errorf("content.%s must be between %d and %d", limit.name, limit.min, limit.max)
		}
	}
	for surface := range c.Content.Surfaces {
		if !IsKnownContentSurface(surface) {
			return fmt.Errorf("content.surfaces contains unknown surface %q", surface)
		}
	}
	for name := range c.Secrets.Detectors {
		if !IsKnownSecretDetector(name) {
			return fmt.Errorf("secrets.detectors contains unknown detector %q", name)
		}
	}
	seenRules := make(map[string]bool, len(c.PathQualification.EnabledRules))
	for _, ruleID := range c.PathQualification.EnabledRules {
		if strings.TrimSpace(ruleID) == "" || ruleID != strings.TrimSpace(ruleID) {
			return fmt.Errorf("path_qualification.enabled_rules cannot contain empty or whitespace-padded rule IDs")
		}
		if !IsKnownPathRule(ruleID) {
			return fmt.Errorf("path_qualification.enabled_rules contains unknown rule %q", ruleID)
		}
		if seenRules[ruleID] {
			return fmt.Errorf("path_qualification.enabled_rules contains duplicate rule %q", ruleID)
		}
		seenRules[ruleID] = true
	}
	hasPrincipals := len(c.PathQualification.AssumedReachPrincipals) > 0
	for vk, list := range c.PathQualification.VantagePrincipals {
		if strings.TrimSpace(vk) == "" {
			return fmt.Errorf("path_qualification.vantage_principals cannot contain an empty vantage key")
		}
		if len(list) > 0 {
			hasPrincipals = true
		}
		for i, p := range list {
			if _, err := graph.ExistingNodeByID(p.EffectiveKind(), p.ObjectID); err != nil {
				return fmt.Errorf("path_qualification.vantage_principals[%q][%d]: %w", vk, i, err)
			}
		}
	}
	if len(c.PathQualification.EnabledRules) > 0 && !hasPrincipals {
		return fmt.Errorf("path_qualification.assumed_reach_principals or vantage_principals is required when path-qualification rules are enabled")
	}
	for i, p := range c.PathQualification.AssumedReachPrincipals {
		if _, err := graph.ExistingNodeByID(p.EffectiveKind(), p.ObjectID); err != nil {
			return fmt.Errorf("path_qualification.assumed_reach_principals[%d]: %w", i, err)
		}
	}
	return nil
}

// TargetInput combines independent target sources without modifying the config.
func (c Config) TargetInput() targets.Input {
	entries := make([]string, 0, len(c.Targets)+len(c.CIDRs))
	entries = append(entries, c.Targets...)
	entries = append(entries, c.CIDRs...)
	return targets.Input{Entries: entries, Files: c.TargetsFiles, Exclude: c.Exclude, ExcludeFiles: c.ExcludeFiles, MaxTargets: c.Bounds.MaxTargets}
}
