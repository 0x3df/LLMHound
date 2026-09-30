// Package config loads and validates the operator's collection policy.
// It does not contact targets, resolve DNS, or perform correlation.
package config

import (
	"fmt"
	"io"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
	"unicode"

	"github.com/0x3df/LLMHound/internal/targets"
	"gopkg.in/yaml.v3"
)

const MaxConfigBytes = 64 << 10

type Config struct {
	Scope        string      `yaml:"scope"`
	VantageKey   string      `yaml:"vantage_key"`
	Targets      []string    `yaml:"targets"`
	CIDRs        []string    `yaml:"cidrs"`
	TargetsFiles []string    `yaml:"targets_files"`
	Exclude      []string    `yaml:"exclude"`
	ExcludeFiles []string    `yaml:"exclude_files"`
	Bounds       Bounds      `yaml:"bounds"`
	Insecure     bool        `yaml:"insecure"`
	UserAgent    string      `yaml:"user_agent"`
	OptIns       OptIns      `yaml:"opt_ins"`
	Correlation  Correlation `yaml:"correlation"`
}

type Bounds struct {
	Concurrency      int           `yaml:"concurrency"`
	PerHostRate      float64       `yaml:"per_host_rate"`
	ConnectTimeout   time.Duration `yaml:"connect_timeout"`
	ResponseTimeout  time.Duration `yaml:"response_timeout"`
	MaxResponseBytes int64         `yaml:"max_response_bytes"`
	MaxPages         int           `yaml:"max_pages"`
	MaxItems         int           `yaml:"max_items"`
	MaxRedirects     int           `yaml:"max_redirects"`
	MaxTargets       int           `yaml:"max_targets"`
}

// OptIns are explicit policy choices for future allowlisted, redacted reads.
// No content reads are implemented by this M1 input-preparation slice.
type OptIns struct {
	ResourceContent      bool `yaml:"resource_content"`
	Prompts              bool `yaml:"prompts"`
	ConfigurationContent bool `yaml:"configuration_content"`
	WorkspaceContent     bool `yaml:"workspace_content"`
}

// Correlation holds policy only; this package never reads mappings or looks up hosts.
type Correlation struct {
	MappingFile      string   `yaml:"mapping_file"`
	ADDomainSuffixes []string `yaml:"ad_domain_suffixes"`
	ReverseDNS       bool     `yaml:"reverse_dns"`
	CELookup         bool     `yaml:"ce_lookup"`
}

func Defaults() Config {
	return Config{Bounds: Bounds{Concurrency: 16, PerHostRate: 2, ConnectTimeout: 3 * time.Second, ResponseTimeout: 10 * time.Second, MaxResponseBytes: 1 << 20, MaxPages: 100, MaxItems: 10000, MaxRedirects: 0, MaxTargets: 4096}, UserAgent: "LLMHound/dev"}
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
		case "exclude":
			c.Exclude = flags.Exclude
		case "exclude-file":
			c.ExcludeFiles = flags.ExcludeFiles
		case "concurrency":
			c.Bounds.Concurrency = flags.Bounds.Concurrency
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
		case "insecure":
			c.Insecure = flags.Insecure
		case "user-agent":
			c.UserAgent = flags.UserAgent
		case "resource-content":
			c.OptIns.ResourceContent = flags.OptIns.ResourceContent
		case "prompts":
			c.OptIns.Prompts = flags.OptIns.Prompts
		case "configuration-content":
			c.OptIns.ConfigurationContent = flags.OptIns.ConfigurationContent
		case "workspace-content":
			c.OptIns.WorkspaceContent = flags.OptIns.WorkspaceContent
		case "mapping-file":
			c.Correlation.MappingFile = flags.Correlation.MappingFile
		case "ad-domain-suffix":
			c.Correlation.ADDomainSuffixes = flags.Correlation.ADDomainSuffixes
		case "reverse-dns":
			c.Correlation.ReverseDNS = flags.Correlation.ReverseDNS
		case "ce-lookup":
			c.Correlation.CELookup = flags.Correlation.CELookup
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
	if len(c.Targets)+len(c.CIDRs)+len(c.TargetsFiles) == 0 {
		return fmt.Errorf("at least one target, CIDR, or targets file is required")
	}
	if len(c.Targets)+len(c.CIDRs)+len(c.TargetsFiles)+len(c.Exclude)+len(c.ExcludeFiles) > targets.MaxInputEntries {
		return fmt.Errorf("too many target/exclusion input entries")
	}
	for _, value := range c.CIDRs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil || prefix.Addr().Is4In6() || prefix != prefix.Masked() {
			return fmt.Errorf("cidrs must contain canonical IP prefixes with no host bits")
		}
	}
	for name, list := range map[string][]string{"targets_files": c.TargetsFiles, "exclude_files": c.ExcludeFiles} {
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
		{"concurrency", int64(b.Concurrency), 1, 256},
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
	for _, suffix := range c.Correlation.ADDomainSuffixes {
		normalized, err := targets.NormalizeHost(suffix)
		if err != nil {
			return fmt.Errorf("correlation.ad_domain_suffixes must contain exact ASCII DNS suffixes: %w", err)
		}
		if _, err := netip.ParseAddr(normalized); err == nil {
			return fmt.Errorf("correlation.ad_domain_suffixes cannot contain IP addresses")
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
