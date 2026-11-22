package transport_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0x3df/LLMHound/internal/config"
	"github.com/0x3df/LLMHound/internal/transport"
)

func TestTransport_SafetyEnforcement(t *testing.T) {
	client := transport.NewClient(transport.Config{
		Bounds: config.Bounds{
			MaxResponseBytes: 1024,
		},
	})
	ctx := context.Background()

	// 1. Forbidden HTTP methods
	disallowedMethods := []string{http.MethodPut, http.MethodDelete, http.MethodPatch, "CUSTOM"}
	for _, m := range disallowedMethods {
		req, err := http.NewRequestWithContext(ctx, m, "http://localhost:11434/api/tags", nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}
		_, err = client.Do(req)
		if err == nil || !errors.Is(err, transport.ErrForbiddenMethod) {
			t.Errorf("expected ErrForbiddenMethod for method %s, got %v", m, err)
		}
	}

	// 2. Forbidden mutating and generation endpoints
	bannedPaths := []string{
		"/api/generate",
		"/api/chat",
		"/api/embeddings",
		"/v1/images/generations",
		"/v1/audio/speech",
		"/api/pull",
		"/api/push",
		"/api/create",
		"/api/delete",
		"/api/copy",
		"/api/blobs",
	}
	for _, path := range bannedPaths {
		_, err := client.Get(ctx, "http://localhost:11434"+path)
		if err == nil || !errors.Is(err, transport.ErrMutationForbidden) {
			t.Errorf("expected ErrMutationForbidden for GET %s, got %v", path, err)
		}

		_, err = client.Post(ctx, "http://localhost:11434"+path, "application/json", []byte(`{}`))
		if err == nil || !errors.Is(err, transport.ErrMutationForbidden) {
			t.Errorf("expected ErrMutationForbidden for POST %s, got %v", path, err)
		}
	}
}

func TestTransport_GetAndLimits(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != "CustomUA/1.0" {
			t.Errorf("expected User-Agent CustomUA/1.0, got %q", r.Header.Get("User-Agent"))
		}
		if r.URL.Path == "/short" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"hello":"world"}`))
			return
		}
		if r.URL.Path == "/long" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(strings.Repeat("A", 200)))
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	client := transport.NewClient(transport.Config{
		Bounds: config.Bounds{
			MaxResponseBytes: 50,
			ResponseTimeout:  5 * time.Second,
		},
		UserAgent: "CustomUA/1.0",
	})
	ctx := context.Background()

	// Short response within bounds
	resp, err := client.Get(ctx, ts.URL+"/short")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if resp.Truncated {
		t.Errorf("expected not truncated")
	}
	if string(resp.Body) != `{"hello":"world"}` {
		t.Errorf("unexpected body: %s", string(resp.Body))
	}

	// Long response truncated at MaxResponseBytes
	resp, err = client.Get(ctx, ts.URL+"/long")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Truncated {
		t.Errorf("expected response to be truncated")
	}
	if len(resp.Body) != 50 {
		t.Errorf("expected body length 50, got %d", len(resp.Body))
	}
}

func TestTransport_TLSInspection(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"version":"0.3.12"}`))
	}))
	defer ts.Close()

	ctx := context.Background()

	// 1. Insecure = false: self-signed httptest cert should fail verification, but record TLS info
	clientStrict := transport.NewClient(transport.Config{
		Bounds:   config.Bounds{MaxResponseBytes: 1024},
		Insecure: false,
	})

	resp, err := clientStrict.Get(ctx, ts.URL+"/api/version")
	if err == nil {
		t.Fatalf("expected TLS verification failure for self-signed cert")
	}
	if resp == nil || resp.TLS == nil {
		t.Fatalf("expected captured TLS info even on failure, got %v", resp)
	}
	if resp.TLS.VerificationResult != "failed" {
		t.Errorf("expected verification_result failed, got %q", resp.TLS.VerificationResult)
	}
	if resp.TLS.CertFingerprint == "" {
		t.Errorf("expected non-empty cert fingerprint")
	}

	// 2. Insecure = true: override allows connection and records unverified_override
	clientInsecure := transport.NewClient(transport.Config{
		Bounds:   config.Bounds{MaxResponseBytes: 1024},
		Insecure: true,
	})

	resp, err = clientInsecure.Get(ctx, ts.URL+"/api/version")
	if err != nil {
		t.Fatalf("unexpected error with Insecure=true: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if resp.TLS == nil {
		t.Fatalf("expected non-nil TLSInfo")
	}
	if resp.TLS.VerificationResult != "unverified_override" {
		t.Errorf("expected unverified_override, got %q", resp.TLS.VerificationResult)
	}
	if !resp.TLS.InsecureOverride {
		t.Errorf("expected InsecureOverride true")
	}
	if resp.TLS.CertFingerprint == "" {
		t.Errorf("expected cert fingerprint to be populated")
	}
	if resp.TLS.ValidFrom == "" || resp.TLS.ValidTo == "" {
		t.Errorf("expected valid validity dates")
	}
}

func TestTransport_Redirects(t *testing.T) {
	var ts *httptest.Server
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/origin":
			http.Redirect(w, r, "/target", http.StatusFound)
		case "/target":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		case "/external":
			http.Redirect(w, r, "http://unauthorized.external.local/data", http.StatusFound)
		}
	}))
	defer ts.Close()

	ctx := context.Background()

	// 1. MaxRedirects = 0 (default): should NOT follow redirect
	clientNoRedirect := transport.NewClient(transport.Config{
		Bounds: config.Bounds{
			MaxRedirects:     0,
			MaxResponseBytes: 1024,
		},
	})
	resp, err := clientNoRedirect.Get(ctx, ts.URL+"/origin")
	if err == nil {
		t.Fatalf("expected error when MaxRedirects=0 and redirect encountered")
	}
	if !errors.Is(err, transport.ErrMaxRedirectsExceeded) {
		t.Errorf("expected ErrMaxRedirectsExceeded, got %v", err)
	}

	// 2. MaxRedirects = 2 and authorized host
	clientRedirect := transport.NewClient(transport.Config{
		Bounds: config.Bounds{
			MaxRedirects:     2,
			MaxResponseBytes: 1024,
		},
		AuthorizedHosts: []string{ts.Listener.Addr().String()},
	})
	resp, err = clientRedirect.Get(ctx, ts.URL+"/origin")
	if err != nil {
		t.Fatalf("unexpected redirect error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if len(resp.Redirects) != 1 {
		t.Fatalf("expected 1 recorded redirect, got %d", len(resp.Redirects))
	}
	if !resp.Redirects[0].Authorized {
		t.Errorf("expected redirect to be authorized")
	}

	// 3. Redirect to unauthorized destination
	resp, err = clientRedirect.Get(ctx, ts.URL+"/external")
	if err == nil {
		t.Fatalf("expected redirect to unauthorized destination to fail")
	}
	if !errors.Is(err, transport.ErrRedirectNotAuthorized) {
		t.Errorf("expected ErrRedirectNotAuthorized, got %v", err)
	}
}

// Ensure transport compiles without unused tls import
var _ = tls.VersionTLS13

func TestTransport_RedirectToBannedPathRefused(t *testing.T) {
	var hit bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/show", "/api/tags":
			http.Redirect(w, r, "/api/pull", http.StatusTemporaryRedirect)
		case "/api/pull":
			hit = true
		}
	}))
	defer ts.Close()

	client := transport.NewClient(transport.Config{
		Bounds: config.Bounds{MaxResponseBytes: 1024, MaxRedirects: 3},
	})
	ctx := context.Background()

	if _, err := client.Get(ctx, ts.URL+"/api/tags"); err == nil || !errors.Is(err, transport.ErrMutationForbidden) {
		t.Errorf("expected ErrMutationForbidden for GET redirect to banned path, got %v", err)
	}
	if _, err := client.Post(ctx, ts.URL+"/api/show", "application/json", []byte(`{"name":"m"}`)); err == nil {
		t.Errorf("expected POST redirect to banned path to be refused")
	}
	if hit {
		t.Errorf("banned path must never be requested via redirect")
	}
}

func TestTransport_NormalizedPathsAndEmbedBanned(t *testing.T) {
	for _, p := range []string{"/api/embed", "/v1/chat/completions", "/v1/completions", "/v1/embeddings", "//api//generate", "/api/tags/../generate"} {
		if err := transport.CheckSafety(http.MethodGet, p); !errors.Is(err, transport.ErrMutationForbidden) {
			t.Errorf("expected ErrMutationForbidden for %s, got %v", p, err)
		}
	}
	if err := transport.CheckSafety(http.MethodGet, "/api/tags"); err != nil {
		t.Errorf("unexpected error for /api/tags: %v", err)
	}
}

func TestTransport_ConcurrentRequestsKeepTLSAndRedirectsPerRequest(t *testing.T) {
	mux := func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hop" {
			http.Redirect(w, r, "/final", http.StatusFound)
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(mux))
	defer tlsSrv.Close()
	plainSrv := httptest.NewServer(http.HandlerFunc(mux))
	defer plainSrv.Close()

	client := transport.NewClient(transport.Config{
		Bounds:   config.Bounds{MaxResponseBytes: 1024, MaxRedirects: 3},
		Insecure: true,
	})

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			resp, err := client.Get(context.Background(), tlsSrv.URL+"/final")
			if err != nil || resp.TLS == nil || len(resp.Redirects) != 0 {
				t.Errorf("tls request: err=%v resp=%+v", err, resp)
			}
		}()
		go func() {
			defer wg.Done()
			resp, err := client.Get(context.Background(), plainSrv.URL+"/hop")
			if err != nil || resp.TLS != nil || len(resp.Redirects) != 1 {
				t.Errorf("plain request: err=%v resp=%+v", err, resp)
			}
		}()
	}
	wg.Wait()
}

func TestTransport_CrossHostRedirectRefusedWithoutAllowlist(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer other.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cross":
			http.Redirect(w, r, other.URL+"/api/tags", http.StatusFound)
		case "/same":
			http.Redirect(w, r, "/api/tags", http.StatusFound)
		}
	}))
	defer origin.Close()

	client := transport.NewClient(transport.Config{
		Bounds: config.Bounds{MaxResponseBytes: 1024, MaxRedirects: 3},
	})
	if _, err := client.Get(context.Background(), origin.URL+"/cross"); !errors.Is(err, transport.ErrRedirectNotAuthorized) {
		t.Errorf("expected ErrRedirectNotAuthorized for cross-host redirect, got %v", err)
	}
	resp, err := client.Get(context.Background(), origin.URL+"/same")
	if err != nil || resp.StatusCode != http.StatusOK || len(resp.Redirects) != 1 {
		t.Errorf("same-host redirect should be followed and recorded: err=%v resp=%+v", err, resp)
	}
}

func TestTLSRejectsWrongIPCertOnIPLiteral(t *testing.T) {
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "wrong-ip"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("198.51.100.1")},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	ts.TLS = &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{leafDER},
			PrivateKey:  leafKey,
		}},
	}
	ts.StartTLS()
	defer ts.Close()

	client := transport.NewClient(transport.Config{
		Bounds:     config.Bounds{MaxResponseBytes: 1024},
		Insecure:   false,
		TLSRootCAs: pool,
	})
	resp, err := client.Get(context.Background(), ts.URL+"/api/version")
	if err == nil {
		t.Fatalf("expected hostname/IP SAN mismatch error on 127.0.0.1 for 198.51.100.1 cert, got %+v", resp)
	}
	if resp == nil || resp.TLS == nil || resp.TLS.VerificationResult != "failed" {
		t.Fatalf("expected TLS verification failed metadata, got %+v", resp)
	}
}

func TestDoRejectsUserinfoAndUnauthorizedInitialHost(t *testing.T) {
	var hit bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	client := transport.NewClient(transport.Config{
		Bounds:          config.Bounds{MaxResponseBytes: 1024},
		AuthorizedHosts: []string{"allowed.example.test"},
	})
	if _, err := client.Get(context.Background(), strings.Replace(ts.URL, "http://", "http://user:pass@", 1)+"/api/tags"); err == nil {
		t.Fatal("expected error when URL contains embedded userinfo")
	}
	if _, err := client.Get(context.Background(), ts.URL+"/api/tags"); !errors.Is(err, transport.ErrRedirectNotAuthorized) {
		t.Fatalf("expected unauthorized initial host rejection, got %v", err)
	}
	if hit {
		t.Fatal("unauthorized or credential-bearing request must not dial")
	}
}

func TestRedirectRejectsHTTPSDowngrade(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer plain.Close()

	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+"/downgraded", http.StatusFound)
	}))
	defer tlsSrv.Close()

	client := transport.NewClient(transport.Config{
		Bounds:          config.Bounds{MaxResponseBytes: 1024, MaxRedirects: 2},
		Insecure:        true,
		AuthorizedHosts: []string{"127.0.0.1"},
	})
	if _, err := client.Get(context.Background(), tlsSrv.URL+"/start"); !errors.Is(err, transport.ErrRedirectNotAuthorized) {
		t.Fatalf("expected https->http downgrade redirect rejection, got %v", err)
	}
}
