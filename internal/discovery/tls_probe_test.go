package discovery_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/0x3df/LLMHound/internal/discovery"
)

func newOllamaTLSServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/version":
			_, _ = w.Write([]byte(`{"version":"0.3.12"}`))
		case "/api/tags":
			_, _ = w.Write([]byte(`{"models":[]}`))
		default:
			_, _ = w.Write([]byte(`Ollama is running`))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestProbe_UntrustedCertificateIsReachableTLSFailure(t *testing.T) {
	srv := newOllamaTLSServer(t)
	res, err := discovery.Probe(context.Background(), &http.Client{}, srv.URL, discovery.OllamaDefinition())
	if err != nil {
		t.Fatal(err)
	}
	if res.Matched || !res.Reachable || !res.TLSFailed {
		t.Fatalf("want reachable, unmatched TLS failure; got %+v", res)
	}
	if !strings.Contains(res.Reason, "TLS certificate verification failed") {
		t.Fatalf("reason must name the TLS failure, got %q", res.Reason)
	}
	if strings.Contains(res.Reason, srv.URL) {
		t.Fatalf("reason must not embed the request URL: %q", res.Reason)
	}
}

func TestProbeWithScheme_TLSFailureCachedAndNotOverwritten(t *testing.T) {
	srv := newOllamaTLSServer(t)
	host, port := hostPort(t, srv.URL)
	cache := discovery.NewPortProbeCache()
	for i := 0; i < 2; i++ { // second pass is served from the cache
		res, err := discovery.ProbeWithScheme(context.Background(), &http.Client{}, host, port, "https", discovery.OllamaDefinition(), cache)
		if err != nil {
			t.Fatal(err)
		}
		if !res.TLSFailed || !res.Reachable {
			t.Fatalf("pass %d: want TLS failure, got %+v", i, res)
		}
	}
}

func TestProbe_TrustedCertificateMatches(t *testing.T) {
	srv := newOllamaTLSServer(t)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	res, err := discovery.Probe(context.Background(), client, srv.URL, discovery.OllamaDefinition())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Matched || res.TLSFailed {
		t.Fatalf("trusted certificate should match, got %+v", res)
	}
}

func hostPort(t *testing.T, rawURL string) (string, int) {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	return u.Hostname(), port
}

func TestLoadDefinitionsRejectsUnsafeProbePaths(t *testing.T) {
	for _, p := range []string{"@evil.example/", "//evil.example/x", "api/version", "/a/../b", "/api/generate", "/x y", "/x#frag", `/x\y`} {
		raw := `[{"surface":"ollama","default_port":11434,"probe_paths":["` + strings.ReplaceAll(p, `\`, `\\`) + `"]}]`
		if _, err := discovery.LoadDefinitions([]byte(raw)); err == nil {
			t.Errorf("probe path %q must be rejected", p)
		}
	}
	if _, err := discovery.LoadDefinitions([]byte(`[{"surface":"ollama","default_port":11434,"probe_paths":["/api/version","/api/tags?x=1"]}]`)); err != nil {
		t.Fatalf("safe probe paths rejected: %v", err)
	}
}
