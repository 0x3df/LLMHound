package mcp

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type redirectInfo struct {
	FromURL    string
	ToURL      string
	StatusCode int
	Authorized bool
	Reason     string
}

type rateLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	last     time.Time
}

func newRateLimiter(rate float64) *rateLimiter {
	if rate <= 0 {
		return nil
	}
	return &rateLimiter{
		interval: time.Duration(float64(time.Second) / rate),
	}
}

func (r *rateLimiter) Wait(ctx context.Context) error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	now := time.Now()
	wait := r.interval - now.Sub(r.last)
	if wait > 0 {
		r.last = now.Add(wait)
		r.mu.Unlock()
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-timer.C:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	r.last = now
	r.mu.Unlock()
	return nil
}

type limitReadCloser struct {
	r     io.Reader
	c     io.Closer
	limit int64
	read  int64
}

func (l *limitReadCloser) Read(p []byte) (int, error) {
	n, err := l.r.Read(p)
	l.read += int64(n)
	if l.read > l.limit {
		return n, fmt.Errorf("response body exceeded limit of %d bytes", l.limit)
	}
	return n, err
}

func (l *limitReadCloser) Close() error {
	return l.c.Close()
}

type trackingTransport struct {
	base             http.RoundTripper
	limiter          *rateLimiter
	maxResponseBytes int64
	userAgent        string
	insecure         bool
	targetHost       string
	targetAuthority  string
	initialScheme    string

	mu             sync.Mutex
	lastStatusCode int
	lastStatusText string
	lastHeaders    http.Header
	tlsState       *tls.ConnectionState
	tlsErr         error
	redirects      []redirectInfo
}

func newTrackingTransport(base http.RoundTripper, rate float64, maxResponseBytes int64, userAgent string, insecure bool, targetHost, canonicalURL string) *trackingTransport {
	if base == nil {
		base = http.DefaultTransport
	}
	var targetAuthority, initialScheme string
	if u, err := url.Parse(canonicalURL); err == nil {
		targetAuthority = canonicalAuthority(u)
		initialScheme = strings.ToLower(u.Scheme)
	}
	return &trackingTransport{
		base:             base,
		limiter:          newRateLimiter(rate),
		maxResponseBytes: maxResponseBytes,
		userAgent:        userAgent,
		insecure:         insecure,
		targetHost:       targetHost,
		targetAuthority:  targetAuthority,
		initialScheme:    initialScheme,
	}
}

func canonicalAuthority(u *url.URL) string {
	if u == nil {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port == "" {
		switch strings.ToLower(u.Scheme) {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
	}
	if port == "" {
		return host
	}
	return net.JoinHostPort(host, port)
}

func (t *trackingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil || req.URL == nil {
		return nil, errors.New("mcp request missing URL")
	}
	scheme := strings.ToLower(req.URL.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("mcp unsupported URL scheme %q", req.URL.Scheme)
	}
	if req.URL.User != nil {
		return nil, errors.New("mcp embedded URL credentials are forbidden")
	}
	if t.initialScheme == "https" && scheme != "https" {
		return nil, errors.New("mcp https to http downgrade forbidden")
	}
	if t.targetHost != "" && !strings.EqualFold(req.URL.Hostname(), t.targetHost) {
		return nil, fmt.Errorf("mcp request host %q outside authorized target %q", req.URL.Hostname(), t.targetHost)
	}
	if t.targetAuthority != "" && !strings.EqualFold(canonicalAuthority(req.URL), t.targetAuthority) {
		return nil, fmt.Errorf("mcp request endpoint %q outside authorized authority %q", req.URL.Host, t.targetAuthority)
	}

	if t.limiter != nil {
		if err := t.limiter.Wait(req.Context()); err != nil {
			return nil, err
		}
	}

	if t.userAgent != "" && req.Header.Get("User-Agent") == "" {
		req = req.Clone(req.Context())
		req.Header.Set("User-Agent", t.userAgent)
	}

	resp, err := t.base.RoundTrip(req)
	t.mu.Lock()
	defer t.mu.Unlock()

	if err != nil {
		// Detect TLS handshake errors
		var certErr *tls.CertificateVerificationError
		if errors.As(err, &certErr) || isTLSError(err) {
			t.tlsErr = err
		}
		return nil, err
	}

	t.lastStatusCode = resp.StatusCode
	t.lastStatusText = resp.Status
	t.lastHeaders = resp.Header.Clone()

	if resp.TLS != nil {
		clonedTLS := *resp.TLS
		t.tlsState = &clonedTLS
	}

	if resp.Body != nil && t.maxResponseBytes > 0 {
		limit := t.maxResponseBytes
		if strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream") {
			// Bound SSE streams cumulatively (8x response cap, min 16 MiB) so an adversarial server cannot OOM the worker.
			limit = t.maxResponseBytes * 8
			if limit < 16<<20 {
				limit = 16 << 20
			}
		}
		resp.Body = &limitReadCloser{
			r:     io.LimitReader(resp.Body, limit+1),
			c:     resp.Body,
			limit: limit,
		}
	}

	return resp, nil
}

func isTLSError(err error) bool {
	if err == nil {
		return false
	}
	var recErr tls.RecordHeaderError
	var certErr *tls.CertificateVerificationError
	var unknownAuth x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	var invalidErr x509.CertificateInvalidError
	return errors.As(err, &recErr) || errors.As(err, &certErr) || errors.As(err, &unknownAuth) ||
		errors.As(err, &hostErr) || errors.As(err, &invalidErr)
}

func (t *trackingTransport) LastStatus() (int, string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.lastStatusCode, t.lastStatusText
}

func (t *trackingTransport) LastHeaders() http.Header {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.lastHeaders.Clone()
}

func (t *trackingTransport) TLSState() (*tls.ConnectionState, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.tlsState, t.tlsErr
}

func (t *trackingTransport) Redirects() []redirectInfo {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]redirectInfo, len(t.redirects))
	copy(out, t.redirects)
	return out
}

func (t *trackingTransport) RecordRedirect(fromURL, toURL string, statusCode int, authorized bool, reason string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.redirects = append(t.redirects, redirectInfo{
		FromURL:    fromURL,
		ToURL:      toURL,
		StatusCode: statusCode,
		Authorized: authorized,
		Reason:     reason,
	})
}

// buildHTTPClient constructs an HTTP client configured with redirect policy, and tracking.
func buildHTTPClient(maxRedirects int, tracker *trackingTransport) *http.Client {
	client := &http.Client{
		Transport: tracker,
	}

	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		statusCode := 0
		if req.Response != nil {
			statusCode = req.Response.StatusCode
		}
		if len(via) > maxRedirects {
			tracker.RecordRedirect(via[len(via)-1].URL.String(), req.URL.String(), statusCode, false, "max redirects exceeded")
			return fmt.Errorf("stopped after %d redirects", maxRedirects)
		}

		// Recheck destination host and scheme: cross-host or https->http downgrade redirects are prohibited
		if req.URL.User != nil {
			tracker.RecordRedirect(via[len(via)-1].URL.String(), req.URL.String(), statusCode, false, "redirect contains embedded credentials")
			return http.ErrUseLastResponse
		}
		if strings.EqualFold(via[0].URL.Scheme, "https") && !strings.EqualFold(req.URL.Scheme, "https") {
			tracker.RecordRedirect(via[len(via)-1].URL.String(), req.URL.String(), statusCode, false, "https to http downgrade redirect forbidden")
			return http.ErrUseLastResponse
		}
		origHost := via[0].URL.Host
		if !strings.EqualFold(req.URL.Host, origHost) {
			tracker.RecordRedirect(via[len(via)-1].URL.String(), req.URL.String(), statusCode, false, "cross-host redirect not authorized")
			return http.ErrUseLastResponse
		}

		tracker.RecordRedirect(via[len(via)-1].URL.String(), req.URL.String(), statusCode, true, "authorized redirect")
		return nil
	}

	return client
}

type tlsObservation struct {
	CertFingerprint    string
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

func extractTLSObservation(state *tls.ConnectionState, tlsErr error, targetHost string, insecure bool) (tlsObservation, bool) {
	if state == nil && tlsErr == nil {
		return tlsObservation{}, false
	}

	obs := tlsObservation{
		InsecureOverride: insecure,
	}

	if tlsErr != nil {
		obs.VerificationResult = "failed"
		obs.VerificationReason = tlsErr.Error()
		return obs, true
	}

	if state != nil {
		switch state.Version {
		case tls.VersionTLS13:
			obs.NegotiatedVersion = "TLS 1.3"
		case tls.VersionTLS12:
			obs.NegotiatedVersion = "TLS 1.2"
		case tls.VersionTLS11:
			obs.NegotiatedVersion = "TLS 1.1"
		case tls.VersionTLS10:
			obs.NegotiatedVersion = "TLS 1.0"
		}

		dnsName := strings.TrimSpace(targetHost)
		if dnsName == "" {
			dnsName = state.ServerName
		}

		if insecure {
			obs.VerificationResult = "unverified_override"
			if len(state.PeerCertificates) > 0 {
				opts := x509.VerifyOptions{
					DNSName:       dnsName,
					Intermediates: x509.NewCertPool(),
				}
				for _, cert := range state.PeerCertificates[1:] {
					opts.Intermediates.AddCert(cert)
				}
				if _, err := state.PeerCertificates[0].Verify(opts); err != nil {
					obs.VerificationReason = err.Error()
				}
			}
		} else {
			obs.VerificationResult = "verified"
		}

		if len(state.PeerCertificates) > 0 {
			leaf := state.PeerCertificates[0]
			sum := sha256.Sum256(leaf.Raw)
			obs.CertFingerprint = strings.ToUpper(hex.EncodeToString(sum[:]))
			obs.Issuer = leaf.Issuer.String()
			obs.Subject = leaf.Subject.String()
			obs.SANs = append([]string(nil), leaf.DNSNames...)
			for _, ip := range leaf.IPAddresses {
				obs.SANs = append(obs.SANs, ip.String())
			}
			obs.ValidFrom = leaf.NotBefore.UTC().Format(time.RFC3339)
			obs.ValidTo = leaf.NotAfter.UTC().Format(time.RFC3339)
		}
		return obs, true
	}

	return tlsObservation{}, false
}
