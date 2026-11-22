package config

import (
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func writeConfig(t *testing.T, data string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "llmhound.yaml")
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadDefaultsAndPaths(t *testing.T) {
	path := writeConfig(t, "scope: tenant\nvantage_key: scanner\ntargets: [AI.Example.Test]\ncidrs: [192.0.2.0/30]\ntargets_files: [hosts.txt]\nexclude_files: [excluded.txt]\nbounds:\n  concurrency: 7\n  connect_timeout: 2s\ninsecure: true\ncontent:\n  surfaces:\n    ollama: false\ncorrelation:\n  mapping_file: computers.json\n")
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Scope != "tenant" || got.Bounds.Concurrency != 7 || got.Bounds.ConnectTimeout != 2*time.Second || got.Bounds.ResponseTimeout != Defaults().Bounds.ResponseTimeout || !got.Insecure {
		t.Fatalf("bad config: %+v", got)
	}
	if !got.Content.Enabled || got.Content.MaxItemBytes != DefaultContentMaxItemBytes || got.Content.EnabledFor("ollama") || !got.Content.EnabledFor("jupyter") {
		t.Fatalf("bad default/surface content config: %+v", got.Content)
	}
	if got.TargetsFiles[0] != filepath.Join(filepath.Dir(path), "hosts.txt") || got.ExcludeFiles[0] != filepath.Join(filepath.Dir(path), "excluded.txt") || got.Correlation.MappingFile != filepath.Join(filepath.Dir(path), "computers.json") {
		t.Fatalf("wrong paths: %+v", got)
	}
	if err := got.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestLoadRejectsInvalidYAML(t *testing.T) {
	for _, data := range []string{
		"scope: x\nscope: y\n", "unknown: true\n", "opt_ins: {prompts: true}\n", "correlation: {ad_domain_suffixes: [corp.example]}\n", "correlation: {reverse_dns: true}\n", "correlation: {ce_lookup: true}\n", "bounds: {max_itemz: 3}\n", "content: {surfaces: []}\n", "content: {surfaces: {ollama: nope}}\n", "scope: null\n", "bounds: null\n", "insecure: null\n", "---\nscope: x\n---\nscope: y\n", "[]\n", "scope: [x]\n", "scope: 123\n", "insecure: yes\n", "bounds: {max_targets: 1.5}\n", "bounds: {concurrency: \"7\"}\n", "scope: &s x\nvantage_key: *s\n", "scope: x\nbounds: {connect_timeout: 7}\n", "scope: x\nbounds: {max_targets: nope}\n", "", strings.Repeat("#", MaxConfigBytes+1),
	} {
		t.Run(data[:min(40, len(data))], func(t *testing.T) {
			if _, err := Load(writeConfig(t, data)); err == nil {
				t.Fatal("accepted malformed config")
			}
		})
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Fatal("accepted missing config")
	}
}

func TestApplyOnlyExplicitFields(t *testing.T) {
	file := Defaults()
	file.Scope, file.VantageKey, file.Insecure = "file-scope", "file-vantage", true
	file.Targets, file.CIDRs, file.TargetsFiles = []string{"file.example.test"}, []string{"192.0.2.0/30"}, []string{"file.txt"}
	file.Bounds.Concurrency = 17
	file.Bounds.MaxRedirects = 5
	file.Content.Enabled = true
	file.Content.Surfaces = map[string]bool{"jupyter": false}
	flags := Defaults()
	flags.Scope = "flag-scope"
	flags.TargetsFiles = []string{"flag.txt"}
	flags.Bounds.MaxRedirects = 0
	flags.Content.Enabled = false
	flags.Content.Surfaces = map[string]bool{"ollama": false}
	got, err := Apply(file, flags, []string{"scope", "targets-file", "insecure", "content", "content-disable", "max-redirects"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Scope != "flag-scope" || got.VantageKey != "file-vantage" || got.Insecure || got.Content.Enabled || !reflect.DeepEqual(got.Content.Surfaces, map[string]bool{"ollama": false}) || got.Bounds.MaxRedirects != 0 || got.Bounds.Concurrency != 17 || !reflect.DeepEqual(got.Targets, file.Targets) || !reflect.DeepEqual(got.CIDRs, file.CIDRs) || !reflect.DeepEqual(got.TargetsFiles, []string{"flag.txt"}) {
		t.Fatalf("bad override: %+v", got)
	}
	flags.Scope = ""
	got, err = Apply(file, flags, []string{"scope"})
	if err != nil || got.Validate() == nil {
		t.Fatal("explicit empty scope not rejected")
	}
	if _, err := Apply(file, flags, []string{"typo"}); err == nil {
		t.Fatal("accepted unknown override")
	}
}

func validConfig() Config {
	c := Defaults()
	c.Scope, c.VantageKey = "tenant", "scanner"
	c.Targets = []string{"ai.example.test"}
	return c
}

func TestValidateBounds(t *testing.T) {
	for name, mutate := range map[string]func(*Config){
		"scope": func(c *Config) { c.Scope = "" }, "vantage": func(c *Config) { c.VantageKey = "" },
		"scope-whitespace": func(c *Config) { c.Scope = " tenant" }, "vantage-control": func(c *Config) { c.VantageKey = "scan\nkey" }, "targets": func(c *Config) { c.Targets = nil },
		"cidr-name":       func(c *Config) { c.CIDRs = []string{"ai.example.test"} },
		"cidr-hostbits":   func(c *Config) { c.CIDRs = []string{"192.0.2.1/24"} },
		"concurrency-low": func(c *Config) { c.Bounds.Concurrency = 0 }, "concurrency-high": func(c *Config) { c.Bounds.Concurrency = 257 },
		"rate": func(c *Config) { c.Bounds.PerHostRate = 0 }, "rate-nan": func(c *Config) { c.Bounds.PerHostRate = math.NaN() }, "rate-inf": func(c *Config) { c.Bounds.PerHostRate = math.Inf(1) },
		"connect": func(c *Config) { c.Bounds.ConnectTimeout = 0 }, "response": func(c *Config) { c.Bounds.ResponseTimeout = time.Hour },
		"bytes": func(c *Config) { c.Bounds.MaxResponseBytes = 0 }, "bytes-high": func(c *Config) { c.Bounds.MaxResponseBytes = 1 << 30 },
		"pages": func(c *Config) { c.Bounds.MaxPages = 0 }, "items": func(c *Config) { c.Bounds.MaxItems = -1 }, "redirects": func(c *Config) { c.Bounds.MaxRedirects = -1 },
		"target-limit": func(c *Config) { c.Bounds.MaxTargets = 65537 }, "user-agent": func(c *Config) { c.UserAgent = "x\r\ny" }, "user-agent-empty": func(c *Config) { c.UserAgent = "" },
		"empty-file": func(c *Config) { c.TargetsFiles = []string{""} }, "empty-mapping": func(c *Config) { c.Correlation.MappingFile = " " },
		"content-item-bytes": func(c *Config) { c.Content.MaxItemBytes = 0 }, "content-items": func(c *Config) { c.Content.MaxItemsPerResource = 0 },
		"content-service-bytes": func(c *Config) { c.Content.MaxServiceBytes = HardMaxContentServiceBytes + 1 }, "content-samples": func(c *Config) { c.Content.MaxSamplePoints = 0 },
		"content-unknown-surface": func(c *Config) { c.Content.Surfaces = map[string]bool{"olama": false} }, "content-case-surface": func(c *Config) { c.Content.Surfaces = map[string]bool{"Ollama": false} },
	} {
		t.Run(name, func(t *testing.T) {
			c := validConfig()
			mutate(&c)
			if err := c.Validate(); err == nil {
				t.Fatal("accepted invalid config")
			}
		})
	}
	if err := validConfig().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestTargetInputKeepsIndependentSources(t *testing.T) {
	c := validConfig()
	c.CIDRs = []string{"192.0.2.0/30"}
	c.TargetsFiles = []string{"hosts.txt"}
	c.Exclude = []string{"192.0.2.1"}
	c.ExcludeFiles = []string{"exclude.txt"}
	got := c.TargetInput()
	if !reflect.DeepEqual(got.Entries, []string{"ai.example.test", "192.0.2.0/30"}) || got.Files[0] != "hosts.txt" || got.Exclude[0] != "192.0.2.1" || got.ExcludeFiles[0] != "exclude.txt" || got.MaxTargets != c.Bounds.MaxTargets {
		t.Fatalf("wrong input: %+v", got)
	}
	got.Entries[0] = "changed.example.test"
	if c.Targets[0] != "ai.example.test" {
		t.Fatal("input mutated config")
	}
}

func TestLoadPreservesInvalidBlankPathsForValidation(t *testing.T) {
	c, err := Load(writeConfig(t, "scope: tenant\nvantage_key: scanner\ntargets_files: [' ']\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Validate() == nil {
		t.Fatal("blank file path accepted after normalization")
	}
}

func TestApplyAllFields(t *testing.T) {
	flags := Config{Scope: "x", VantageKey: "v", Targets: []string{"a.example.test"}, CIDRs: []string{"192.0.2.0/30"}, TargetsFiles: []string{"a.txt"}, Exclude: []string{"b.example.test"}, ExcludeFiles: []string{"b.txt"}, Bounds: Bounds{Concurrency: 2, PerHostRate: 3, ConnectTimeout: time.Second, ResponseTimeout: 2 * time.Second, MaxResponseBytes: 10, MaxPages: 20, MaxItems: 30, MaxRedirects: 1, MaxTargets: 40}, Insecure: true, UserAgent: "test", Content: Content{Enabled: false, MaxItemBytes: 100, MaxItemsPerResource: 2, MaxServiceBytes: 300, MaxSamplePoints: 3, Surfaces: map[string]bool{"ollama": false}}, Correlation: Correlation{MappingFile: "m.json"}}
	keys := []string{"scope", "vantage", "targets", "cidr", "targets-file", "exclude", "exclude-file", "concurrency", "per-host-rate", "connect-timeout", "response-timeout", "max-response-bytes", "max-pages", "max-items", "max-redirects", "max-targets", "insecure", "user-agent", "content", "content-max-item-bytes", "content-max-items-per-resource", "content-max-service-bytes", "content-max-sample-points", "content-disable", "mapping-file"}
	got, err := Apply(Defaults(), flags, keys)
	if err != nil || !reflect.DeepEqual(got, flags) {
		t.Fatalf("incomplete overrides: %+v %v", got, err)
	}
}

func TestSecretsDetectorConfig(t *testing.T) {
	c, err := Load(writeConfig(t, "scope: tenant\nvantage_key: scanner\ntargets: [AI.Example.Test]\nsecrets:\n  detectors:\n    github_token: false\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Secrets.DetectorEnabled("github_token") {
		t.Fatal("explicitly disabled detector must be disabled")
	}
	if !c.Secrets.DetectorEnabled("private_key") || !c.Secrets.DetectorEnabled("aws_access_key") {
		t.Fatal("missing key must default to enabled")
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	unknown, err := Load(writeConfig(t, "scope: tenant\nvantage_key: scanner\ntargets: [AI.Example.Test]\nsecrets:\n  detectors:\n    openai_key: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := unknown.Validate(); err == nil || !strings.Contains(err.Error(), `secrets.detectors contains unknown detector "openai_key"`) {
		t.Fatalf("unknown detector must fail validation, got: %v", err)
	}
}

func TestPathQualificationConfigValidation(t *testing.T) {
	// Valid enabled config.
	valid, err := Load(writeConfig(t, "scope: tenant\nvantage_key: scanner\ntargets: [AI.Example.Test]\npath_qualification:\n  enabled_rules: [jupyter-auth-disabled, ray-anonymous-jobs]\n  assumed_reach_principals:\n    - object_id: S-1-5-21-1-2-3-513\n      kind: Group\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid path_qualification rejected: %v", err)
	}

	// Enabled without principals fails.
	noPrincipals, err := Load(writeConfig(t, "scope: tenant\nvantage_key: scanner\ntargets: [AI.Example.Test]\npath_qualification:\n  enabled_rules: [jupyter-auth-disabled]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := noPrincipals.Validate(); err == nil || !strings.Contains(err.Error(), "assumed_reach_principals") {
		t.Fatalf("expected missing assumed_reach_principals error, got: %v", err)
	}

	// Unknown rule fails.
	unknownRule, err := Load(writeConfig(t, "scope: tenant\nvantage_key: scanner\ntargets: [AI.Example.Test]\npath_qualification:\n  enabled_rules: [nonexistent-rule]\n  assumed_reach_principals:\n    - object_id: S-1-5-21-1-2-3-513\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := unknownRule.Validate(); err == nil || !strings.Contains(err.Error(), "unknown rule") {
		t.Fatalf("expected unknown rule error, got: %v", err)
	}
}
