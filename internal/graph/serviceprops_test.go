package graph

import (
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestServiceFactsOmitsUnknowns(t *testing.T) {
	p := ServiceFacts{Name: "X"}.Properties()
	for _, k := range []string{"auth_advertised", "exec_surface", "exec_surface_basis", "tls_verification", "product"} {
		if _, ok := p[k]; ok {
			t.Errorf("%s must be omitted when unset", k)
		}
	}
}

func TestServiceFactsExecSurface(t *testing.T) {
	p := ServiceFacts{ExecSurface: []string{"terminal", "code_kernel", "terminal"}, ExecSurfaceBasis: BasisInferred}.Properties()
	if got := p["exec_surface"]; !reflect.DeepEqual(got, []string{"code_kernel", "terminal"}) {
		t.Fatalf("exec_surface = %v", got)
	}
	if p["exec_surface_basis"] != "inferred" {
		t.Fatal("basis missing")
	}
	// A surface without a valid basis is never emitted.
	if _, ok := (ServiceFacts{ExecSurface: []string{"terminal"}}).Properties()["exec_surface"]; ok {
		t.Fatal("exec_surface emitted without basis")
	}
}

func TestServiceFactsAuthAdvertised(t *testing.T) {
	p := ServiceFacts{AuthAdvertised: "required"}.Properties()
	if p["auth_advertised"] != "required" || p["auth_advertised_basis"] != "declared" {
		t.Fatalf("got %v", p)
	}
	if _, ok := (ServiceFacts{AuthAdvertised: "bogus"}).Properties()["auth_advertised"]; ok {
		t.Fatal("invalid value emitted")
	}
}

func TestTLSProperties(t *testing.T) {
	f := ServiceFacts{TLS: &TLSSummary{Result: "failed", Reason: "x509:\nbad\x00cert", LeafSHA256: "ABCDEF", Issuer: "CN=ca", NotAfter: "2030-01-01T00:00:00Z"}}
	p := f.tlsProperties()
	if p["tls_verification"] != "failed" || p["tls_leaf_sha256"] != "abcdef" || p["tls_failure_reason"] != "x509:badcert" {
		t.Fatalf("got %v", p)
	}
	if v := (ServiceFacts{TLS: &TLSSummary{Result: "verified"}}).tlsProperties()["tls_verification"]; v != "ok" {
		t.Fatalf("verified -> %v", v)
	}
	if v := (ServiceFacts{TLS: &TLSSummary{Result: "success"}}).tlsProperties()["tls_verification"]; v != "ok" {
		t.Fatalf("success -> %v", v)
	}
	overrideWithErr := (ServiceFacts{TLS: &TLSSummary{Result: "unverified_override", InsecureSet: true, Reason: "x509: unknown authority"}}).tlsProperties()
	if overrideWithErr["tls_verification"] != "insecure_override" || overrideWithErr["tls_failure_reason"] != "x509: unknown authority" {
		t.Fatalf("unverified_override -> %v", overrideWithErr)
	}
	overrideVerified := (ServiceFacts{TLS: &TLSSummary{Result: "verified", InsecureSet: true, Reason: "certificate verified successfully"}}).tlsProperties()
	if overrideVerified["tls_verification"] != "insecure_override" {
		t.Fatalf("override -> %v", overrideVerified)
	}
	if _, ok := overrideVerified["tls_failure_reason"]; ok {
		t.Fatalf("verified override must not copy success reason into tls_failure_reason: %v", overrideVerified)
	}
	if v := (ServiceFacts{TLS: &TLSSummary{}}).tlsProperties(); len(v) != 0 {
		t.Fatalf("empty TLS must emit nothing: %v", v)
	}
	multiByte := strings.Repeat("a", maxReasonLen-1) + "é"
	if got := boundReason(multiByte); !utf8.ValidString(got) || len(got) > maxReasonLen {
		t.Fatalf("boundReason split UTF-8: %q", got)
	}
}

func TestServiceFactsContentSummary(t *testing.T) {
	if p := (ServiceFacts{Name: "X"}).Properties(); p["content_bytes"] != nil {
		t.Fatalf("unset content must be omitted: %v", p)
	}
	if p := (ServiceFacts{Content: &ContentSummary{Collected: false, Bytes: 10}}).Properties(); p["content_bytes"] != nil {
		t.Fatalf("uncollected content must be omitted: %v", p)
	}
	sysPresent := true
	cfgCollected := false
	p := (ServiceFacts{
		Content: &ContentSummary{
			Collected:           true,
			Bytes:               420,
			Truncated:           true,
			SystemPromptPresent: &sysPresent,
			ConfigCollected:     &cfgCollected,
		},
	}).Properties()
	if p["content_bytes"] != int64(420) || p["content_truncated"] != true || p["system_prompt_present"] != true || p["config_collected"] != false {
		t.Fatalf("unexpected content properties: %v", p)
	}
	if _, ok := p["has_exposed_secret"]; ok {
		t.Fatalf("no findings must not set secret properties: %v", p)
	}
	if _, ok := p["secret_types"]; ok {
		t.Fatalf("no findings must not set secret_types: %v", p)
	}
	if _, ok := p["secret_last_confirmed"]; ok {
		t.Fatalf("no findings must not set secret_last_confirmed: %v", p)
	}

	confirmed := time.Date(2026, 11, 21, 10, 30, 0, 0, time.FixedZone("cest", 2*3600))
	p = (ServiceFacts{
		Content: &ContentSummary{
			Collected:         true,
			Bytes:             420,
			SecretTypes:       []string{"private_key", "github_token", "github_token"},
			SecretConfirmedAt: confirmed,
		},
	}).Properties()
	if p["has_exposed_secret"] != true {
		t.Fatalf("has_exposed_secret = %v, want true", p["has_exposed_secret"])
	}
	if got := p["secret_types"].([]string); len(got) != 2 || got[0] != "github_token" || got[1] != "private_key" {
		t.Fatalf("secret_types = %v, want [github_token private_key]", p["secret_types"])
	}
	if got := p["secret_last_confirmed"]; got != "2026-11-21T08:30:00Z" {
		t.Fatalf("secret_last_confirmed = %v, want RFC3339 UTC", got)
	}
}

func TestServiceFactsEndpointAndHTTP(t *testing.T) {
	ep, err := ParseEndpoint("http://ai1.example:8888/lab", "")
	if err != nil {
		t.Fatal(err)
	}
	p := ServiceFacts{Endpoint: ep, TLS: &TLSSummary{Result: "verified"}}.Properties()
	if p["endpoint_scheme"] != "http" || p["endpoint_host"] != "ai1.example" || p["endpoint_port"] != 8888 || p["endpoint_base_path"] != "/lab" {
		t.Fatalf("endpoint props: %v", p)
	}
	if p["tls_verification"] != "n_a" {
		t.Fatalf("plain http must be n_a, got %v", p["tls_verification"])
	}
}
