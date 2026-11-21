package graph

import (
	"reflect"
	"testing"
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
	if v := (ServiceFacts{TLS: &TLSSummary{Result: "verified", InsecureSet: true}}).tlsProperties()["tls_verification"]; v != "insecure_override" {
		t.Fatalf("override -> %v", v)
	}
	if v := (ServiceFacts{TLS: &TLSSummary{}}).tlsProperties(); len(v) != 0 {
		t.Fatalf("empty TLS must emit nothing: %v", v)
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
