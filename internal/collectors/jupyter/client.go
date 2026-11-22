package jupyter

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
	"strings"
	"time"

	"github.com/0x3df/LLMHound/internal/config"
)

var (
	ErrResponseTooLarge = errors.New("response body exceeded max allowed bytes")
)

type httpClient struct {
	client           *http.Client
	maxResponseBytes int64
	userAgent        string
	insecure         bool
}

type httpResponse struct {
	StatusCode  int
	Header      http.Header
	Body        []byte
	TLS         TLSInfo
	IsHTML      bool
	RedirectURL string
}

func newHTTPClient(bounds config.Bounds, insecure bool, userAgent string) *httpClient {
	connectTimeout := bounds.ConnectTimeout
	if connectTimeout <= 0 {
		connectTimeout = 3 * time.Second
	}
	responseTimeout := bounds.ResponseTimeout
	if responseTimeout <= 0 {
		responseTimeout = 10 * time.Second
	}
	maxBytes := bounds.MaxResponseBytes
	if maxBytes <= 0 {
		maxBytes = 1 << 20 // 1 MB default
	}
	maxRedirects := bounds.MaxRedirects
	if maxRedirects < 0 {
		maxRedirects = 0
	}
	ua := userAgent
	if strings.TrimSpace(ua) == "" {
		ua = "LLMHound/dev"
	}

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   connectTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecure,
		},
		MaxIdleConns:          16,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: responseTimeout,
	}

	client := &http.Client{
		Transport:     transport,
		Timeout:       responseTimeout,
		CheckRedirect: makeCheckRedirect(maxRedirects),
	}

	return &httpClient{
		client:           client,
		maxResponseBytes: maxBytes,
		userAgent:        ua,
		insecure:         insecure,
	}
}

func (c *httpClient) Get(ctx context.Context, targetURL string) (*httpResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	if req.URL.User != nil {
		return nil, errors.New("embedded URL credentials are forbidden")
	}

	req.Header.Set("Accept", "application/json, text/html;q=0.9, */*;q=0.8")
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.client.Do(req)
	if err != nil {
		if tlsInfo, ok := extractTLSErrorInfo(err, c.insecure); ok {
			return &httpResponse{TLS: tlsInfo}, err
		}
		return nil, err
	}
	defer resp.Body.Close()

	var tlsInfo TLSInfo
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		tlsInfo = buildTLSInfo(resp.TLS.PeerCertificates[0], tlsVersionString(resp.TLS.Version), c.insecure)
	}

	limitReader := io.LimitReader(resp.Body, c.maxResponseBytes+1)
	body, err := io.ReadAll(limitReader)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	if int64(len(body)) > c.maxResponseBytes {
		return nil, ErrResponseTooLarge
	}

	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	isHTML := strings.Contains(contentType, "text/html")

	redirectURL := resp.Header.Get("Location")

	return &httpResponse{
		StatusCode:  resp.StatusCode,
		Header:      resp.Header,
		Body:        body,
		TLS:         tlsInfo,
		IsHTML:      isHTML,
		RedirectURL: redirectURL,
	}, nil
}

func buildTLSInfo(leaf *x509.Certificate, negVersion string, insecure bool) TLSInfo {
	hash := sha256.Sum256(leaf.Raw)
	var sans []string
	sans = append(sans, leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		sans = append(sans, ip.String())
	}
	info := TLSInfo{
		Observed:           true,
		Fingerprint:        strings.ToUpper(hex.EncodeToString(hash[:])),
		Issuer:             leaf.Issuer.String(),
		Subject:            leaf.Subject.String(),
		SANs:               sans,
		ValidFrom:          leaf.NotBefore.UTC().Format(time.RFC3339),
		ValidTo:            leaf.NotAfter.UTC().Format(time.RFC3339),
		NegotiatedVersion:  negVersion,
		InsecureOverride:   insecure,
		VerificationResult: "verified",
		VerificationReason: "certificate verified successfully",
	}
	if insecure {
		info.VerificationResult = "insecure_override"
		info.VerificationReason = "tls verification disabled by policy"
	}
	return info
}

func extractTLSErrorInfo(err error, insecure bool) (TLSInfo, bool) {
	if err == nil {
		return TLSInfo{}, false
	}
	var certErr *tls.CertificateVerificationError
	var unknownAuth x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	var invalidErr x509.CertificateInvalidError
	var recErr tls.RecordHeaderError
	if errors.As(err, &certErr) {
		var info TLSInfo
		if len(certErr.UnverifiedCertificates) > 0 {
			info = buildTLSInfo(certErr.UnverifiedCertificates[0], "", false)
		} else {
			info = TLSInfo{Observed: true}
		}
		info.VerificationResult = "failed"
		info.VerificationReason = err.Error()
		info.InsecureOverride = insecure
		return info, true
	}
	if errors.As(err, &unknownAuth) || errors.As(err, &hostErr) || errors.As(err, &invalidErr) || errors.As(err, &recErr) {
		return TLSInfo{
			Observed:           true,
			VerificationResult: "failed",
			VerificationReason: err.Error(),
			InsecureOverride:   insecure,
		}, true
	}
	return TLSInfo{}, false
}

func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return fmt.Sprintf("TLS 0x%04x", v)
	}
}

func makeCheckRedirect(maxRedirects int) func(req *http.Request, via []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) > maxRedirects {
			return http.ErrUseLastResponse
		}
		if req.URL.User != nil {
			return http.ErrUseLastResponse
		}
		if len(via) > 0 {
			if strings.EqualFold(via[0].URL.Scheme, "https") && !strings.EqualFold(req.URL.Scheme, "https") {
				return http.ErrUseLastResponse
			}
			if !strings.EqualFold(req.URL.Host, via[0].URL.Host) {
				// Stop cross-scope redirects
				return http.ErrUseLastResponse
			}
		}
		loc := strings.ToLower(req.URL.Path)
		if strings.Contains(loc, "login") || strings.Contains(loc, "tree") {
			return http.ErrUseLastResponse
		}
		return nil
	}
}
