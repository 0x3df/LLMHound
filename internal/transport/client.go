// Package transport provides bounded, safe, read-only HTTP transport for collectors.
// It enforces method allowlists, blocks generation/mutation endpoints, captures
// TLS certificate metadata, controls redirect authorization, and bounds response sizes.
package transport

import (
	"bytes"
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
	"net/http/httptrace"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/0x3df/LLMHound/internal/config"
)

var (
	// ErrForbiddenMethod is returned when an HTTP method other than GET or POST is attempted.
	ErrForbiddenMethod = errors.New("HTTP method forbidden: collectors only perform allowlisted read-only operations")

	// ErrMutationForbidden is returned when a mutating or generation endpoint is requested.
	ErrMutationForbidden = errors.New("operation rejected by safety policy: mutating and generation endpoints are strictly forbidden")

	// ErrRedirectNotAuthorized is returned when a redirect target is outside authorized targets.
	ErrRedirectNotAuthorized = errors.New("redirect target not authorized")

	// ErrMaxRedirectsExceeded is returned when redirects exceed configured limit.
	ErrMaxRedirectsExceeded = errors.New("maximum redirects exceeded")
)

// Banned path prefixes for LLM inference / generation / mutations.
var bannedPathPrefixes = []string{
	"/api/generate",
	"/api/chat",
	"/api/embed",
	"/v1/chat/completions",
	"/v1/completions",
	"/v1/embeddings",
	"/v1/images/generations",
	"/v1/audio/",
	"/api/pull",
	"/api/push",
	"/api/create",
	"/api/delete",
	"/api/copy",
	"/api/blobs",
}

// TLSInfo records leaf certificate and negotiated connection details.
type TLSInfo struct {
	CertFingerprint    string   `json:"cert_fingerprint,omitempty"`
	Issuer             string   `json:"issuer,omitempty"`
	Subject            string   `json:"subject,omitempty"`
	SANs               []string `json:"sans,omitempty"`
	ValidFrom          string   `json:"valid_from,omitempty"`
	ValidTo            string   `json:"valid_to,omitempty"`
	VerificationResult string   `json:"verification_result,omitempty"` // "verified", "failed", "unverified_override"
	VerificationReason string   `json:"verification_reason,omitempty"`
	NegotiatedVersion  string   `json:"negotiated_version,omitempty"`
	InsecureOverride   bool     `json:"insecure_override,omitempty"`
}

// RedirectInfo records an observed redirect hop.
type RedirectInfo struct {
	FromURL    string `json:"from_url"`
	ToURL      string `json:"to_url"`
	StatusCode int    `json:"status_code"`
	Authorized bool   `json:"authorized"`
	Reason     string `json:"reason,omitempty"`
}

// Response encapsulates a bounded HTTP response and captured transport metadata.
type Response struct {
	StatusCode int
	Header     http.Header
	Body       []byte
	Truncated  bool
	TLS        *TLSInfo
	Redirects  []RedirectInfo
}

// Client wraps an HTTP client with collection safety rules.
type Client struct {
	httpClient      *http.Client
	bounds          config.Bounds
	insecure        bool
	userAgent       string
	authorizedHosts map[string]bool
}

type captureKey struct{}

type capture struct {
	mu        sync.Mutex
	tls       *TLSInfo
	redirects []RedirectInfo
}

func (cp *capture) setTLS(info *TLSInfo) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.tls = info
}

func (cp *capture) addRedirect(rec RedirectInfo) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.redirects = append(cp.redirects, rec)
}

// Config defines options for creating a transport Client.
type Config struct {
	Bounds          config.Bounds
	Insecure        bool
	UserAgent       string
	AuthorizedHosts []string
	DialContext     func(ctx context.Context, network, addr string) (net.Conn, error)
}

// NewClient constructs a Client configured with collection safety and bounds.
func NewClient(cfg Config) *Client {
	bounds := cfg.Bounds
	if bounds.ConnectTimeout <= 0 {
		bounds.ConnectTimeout = 3 * time.Second
	}
	if bounds.ResponseTimeout <= 0 {
		bounds.ResponseTimeout = 10 * time.Second
	}
	if bounds.MaxResponseBytes <= 0 {
		bounds.MaxResponseBytes = 1 << 20 // 1 MB default
	}

	userAgent := cfg.UserAgent
	if userAgent == "" {
		userAgent = "LLMHound/dev"
	}

	authMap := make(map[string]bool)
	for _, h := range cfg.AuthorizedHosts {
		normalized := strings.ToLower(strings.TrimSpace(h))
		if normalized != "" {
			authMap[normalized] = true
			if host, _, err := net.SplitHostPort(normalized); err == nil {
				authMap[host] = true
			}
		}
	}

	c := &Client{
		bounds:          bounds,
		insecure:        cfg.Insecure,
		userAgent:       userAgent,
		authorizedHosts: authMap,
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // Verification handled in VerifyConnection callback to capture metadata
		VerifyConnection: func(cs tls.ConnectionState) error {
			_, err := inspectTLS(cs, cfg.Insecure)
			return err
		},
	}

	dialContext := cfg.DialContext
	if dialContext == nil {
		dialContext = (&net.Dialer{
			Timeout:   bounds.ConnectTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext
	}

	dialTLS := func(ctx context.Context, network, addr string) (net.Conn, error) {
		raw, err := dialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		host, _, splitErr := net.SplitHostPort(addr)
		if splitErr != nil {
			host = addr
		}
		cp, _ := ctx.Value(captureKey{}).(*capture)
		conf := tlsConfig.Clone()
		conf.ServerName = host
		conf.VerifyConnection = func(cs tls.ConnectionState) error {
			info, verr := inspectTLS(cs, cfg.Insecure)
			if cp != nil {
				cp.setTLS(info)
			}
			return verr
		}
		hsCtx, cancel := context.WithTimeout(ctx, bounds.ConnectTimeout)
		defer cancel()
		conn := tls.Client(raw, conf)
		if err := conn.HandshakeContext(hsCtx); err != nil {
			_ = raw.Close()
			return nil, err
		}
		return conn, nil
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialContext,
		DialTLSContext:        dialTLS,
		TLSClientConfig:       tlsConfig,
		ResponseHeaderTimeout: bounds.ResponseTimeout,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   bounds.ConnectTimeout,
		ExpectContinueTimeout: 1 * time.Second,
	}

	c.httpClient = &http.Client{
		Transport: transport,
		Timeout:   bounds.ResponseTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			cp, _ := req.Context().Value(captureKey{}).(*capture)
			if cp == nil {
				cp = &capture{}
			}

			fromURL := ""
			status := 0
			if len(via) > 0 {
				last := via[len(via)-1]
				fromURL = last.URL.String()
				if last.Response != nil {
					status = last.Response.StatusCode
				}
			}

			// Check max redirects limit
			if len(via) > bounds.MaxRedirects {
				rec := RedirectInfo{
					FromURL:    fromURL,
					ToURL:      req.URL.String(),
					StatusCode: status,
					Authorized: false,
					Reason:     "exceeded max_redirects limit",
				}
				cp.addRedirect(rec)
				return ErrMaxRedirectsExceeded
			}

			if err := CheckSafety(req.Method, req.URL.Path); err != nil || req.Method != http.MethodGet {
				if err == nil {
					err = fmt.Errorf("%w: redirected %s", ErrForbiddenMethod, req.Method)
				}
				rec := RedirectInfo{
					FromURL:    fromURL,
					ToURL:      req.URL.String(),
					StatusCode: status,
					Authorized: false,
					Reason:     "redirect violates read-only policy",
				}
				cp.addRedirect(rec)
				return err
			}

			{
				host := strings.ToLower(req.URL.Hostname())
				hostWithPort := strings.ToLower(req.URL.Host)
				sameHost := len(via) > 0 && strings.EqualFold(via[0].URL.Host, req.URL.Host)
				if !sameHost && !c.authorizedHosts[host] && !c.authorizedHosts[hostWithPort] {
					rec := RedirectInfo{
						FromURL:    fromURL,
						ToURL:      req.URL.String(),
						StatusCode: status,
						Authorized: false,
						Reason:     "redirect destination not in authorized targets",
					}
					cp.addRedirect(rec)
					return ErrRedirectNotAuthorized
				}
			}

			rec := RedirectInfo{
				FromURL:    fromURL,
				ToURL:      req.URL.String(),
				StatusCode: status,
				Authorized: true,
			}
			cp.addRedirect(rec)
			return nil
		},
	}

	return c
}

func inspectTLS(cs tls.ConnectionState, insecure bool) (*TLSInfo, error) {
	info := &TLSInfo{InsecureOverride: insecure}
	if len(cs.PeerCertificates) == 0 {
		return info, nil
	}
	leaf := cs.PeerCertificates[0]
	sum := sha256.Sum256(leaf.Raw)
	info.CertFingerprint = strings.ToUpper(hex.EncodeToString(sum[:]))
	info.Issuer = leaf.Issuer.String()
	info.Subject = leaf.Subject.String()
	info.SANs = append([]string(nil), leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		info.SANs = append(info.SANs, ip.String())
	}
	info.ValidFrom = leaf.NotBefore.UTC().Format(time.RFC3339)
	info.ValidTo = leaf.NotAfter.UTC().Format(time.RFC3339)
	info.NegotiatedVersion = formatTLSVersion(cs.Version)

	opts := x509.VerifyOptions{
		DNSName:       cs.ServerName,
		Intermediates: x509.NewCertPool(),
	}
	for _, cert := range cs.PeerCertificates[1:] {
		opts.Intermediates.AddCert(cert)
	}
	if _, err := leaf.Verify(opts); err != nil {
		info.VerificationReason = err.Error()
		if insecure {
			info.VerificationResult = "unverified_override"
			return info, nil
		}
		info.VerificationResult = "failed"
		return info, fmt.Errorf("TLS certificate verification failed: %w", err)
	}
	info.VerificationResult = "verified"
	return info, nil
}

// CheckSafety verifies that the request method and path obey strict read-only collection policy.
func CheckSafety(method, rawPath string) error {
	method = strings.ToUpper(method)
	if method != http.MethodGet && method != http.MethodPost {
		return fmt.Errorf("%w: %s", ErrForbiddenMethod, method)
	}

	lowerPath := strings.ToLower(path.Clean("/" + rawPath))
	for _, banned := range bannedPathPrefixes {
		if strings.HasPrefix(lowerPath, banned) {
			return fmt.Errorf("%w: path %q matches generation/mutation prefix %q", ErrMutationForbidden, rawPath, banned)
		}
	}
	return nil
}

// Do executes a bounded, safety-checked HTTP request.
func (c *Client) Do(req *http.Request) (*Response, error) {
	if err := CheckSafety(req.Method, req.URL.Path); err != nil {
		return nil, err
	}

	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", c.userAgent)
	}

	cp := &capture{}
	ctx := context.WithValue(req.Context(), captureKey{}, cp)
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(gc httptrace.GotConnInfo) {
			if tc, ok := gc.Conn.(*tls.Conn); ok && gc.Reused {
				if info, _ := inspectTLS(tc.ConnectionState(), c.insecure); info != nil {
					cp.setTLS(info)
				}
			}
		},
	})
	resp, err := c.httpClient.Do(req.WithContext(ctx))
	cp.mu.Lock()
	tlsInfo, redirects := cp.tls, append([]RedirectInfo(nil), cp.redirects...)
	cp.mu.Unlock()

	if err != nil {
		// Include captured TLS info in partial error metadata if available
		return &Response{
			TLS:       tlsInfo,
			Redirects: redirects,
		}, err
	}
	defer resp.Body.Close()

	limit := c.bounds.MaxResponseBytes
	reader := io.LimitReader(resp.Body, limit+1)
	body, readErr := io.ReadAll(reader)
	if readErr != nil {
		return nil, fmt.Errorf("read response body: %w", readErr)
	}

	truncated := false
	if int64(len(body)) > limit {
		truncated = true
		body = body[:limit]
	}

	return &Response{
		StatusCode: resp.StatusCode,
		Header:     resp.Header.Clone(),
		Body:       body,
		Truncated:  truncated,
		TLS:        tlsInfo,
		Redirects:  redirects,
	}, nil
}

// Get performs an allowlisted GET request with safety bounds.
func (c *Client) Get(ctx context.Context, urlStr string) (*Response, error) {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("parse url: %w", err)
	}
	if err := CheckSafety(http.MethodGet, parsedURL.Path); err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	return c.Do(req)
}

// Post performs an allowlisted read-only POST request (e.g. for opt-in metadata queries).
func (c *Client) Post(ctx context.Context, urlStr, contentType string, body []byte) (*Response, error) {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("parse url: %w", err)
	}
	if err := CheckSafety(http.MethodPost, parsedURL.Path); err != nil {
		return nil, err
	}

	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, urlStr, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return c.Do(req)
}

func formatTLSVersion(ver uint16) string {
	switch ver {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("TLS 0x%04X", ver)
	}
}
