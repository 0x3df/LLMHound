package transport

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// HostRateLimiter spaces requests to each host (hostname, all ports) at a fixed
// interval. One limiter is shared by discovery probes and every collector in a
// scan, so bounds.per_host_rate is the rate a target actually observes rather
// than a per-collector allowance. A nil limiter never waits.
type HostRateLimiter struct {
	interval time.Duration
	mu       sync.Mutex
	hosts    map[string]*hostSlot
}

type hostSlot struct {
	mu   sync.Mutex
	next time.Time
}

// NewHostRateLimiter returns a limiter allowing perSecond requests per host, or
// nil (no limiting) when perSecond is not positive.
func NewHostRateLimiter(perSecond float64) *HostRateLimiter {
	if perSecond <= 0 {
		return nil
	}
	return &HostRateLimiter{
		interval: time.Duration(float64(time.Second) / perSecond),
		hosts:    make(map[string]*hostSlot),
	}
}

// Wait blocks until a request to host may be sent or ctx is done.
func (l *HostRateLimiter) Wait(ctx context.Context, host string) error {
	if l == nil || l.interval <= 0 {
		return nil
	}
	key := strings.ToLower(strings.TrimSpace(host))
	if key == "" {
		return nil
	}
	l.mu.Lock()
	slot, ok := l.hosts[key]
	if !ok {
		slot = &hostSlot{}
		l.hosts[key] = slot
	}
	l.mu.Unlock()

	// Reserve the next send time under the slot lock, then sleep outside it so
	// concurrent callers queue in reservation order.
	slot.mu.Lock()
	now := time.Now()
	at := slot.next
	if at.Before(now) {
		at = now
	}
	slot.next = at.Add(l.interval)
	slot.mu.Unlock()

	wait := time.Until(at)
	if wait <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// RateLimitRoundTripper wraps base so every request, including redirect hops,
// waits on limiter for its destination host.
func RateLimitRoundTripper(base http.RoundTripper, limiter *HostRateLimiter) http.RoundTripper {
	if limiter == nil {
		return base
	}
	if base == nil {
		base = http.DefaultTransport
	}
	return rateLimitedTransport{base: base, limiter: limiter}
}

type rateLimitedTransport struct {
	base    http.RoundTripper
	limiter *HostRateLimiter
}

func (t rateLimitedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := t.limiter.Wait(req.Context(), req.URL.Hostname()); err != nil {
		return nil, err
	}
	return t.base.RoundTrip(req)
}

// CloseIdleConnections forwards to the wrapped transport when supported.
func (t rateLimitedTransport) CloseIdleConnections() {
	if c, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}

// ProxyFunc returns the proxy selector for an explicit, operator-configured
// proxy URL, or nil for a direct connection. Environment proxy variables
// (HTTP_PROXY, HTTPS_PROXY) are deliberately ignored: routing scan traffic
// through an unannounced proxy changes the vantage the evidence claims.
func ProxyFunc(proxy string) (func(*http.Request) (*url.URL, error), error) {
	proxy = strings.TrimSpace(proxy)
	if proxy == "" {
		return nil, nil
	}
	u, err := url.Parse(proxy)
	if err != nil {
		return nil, fmt.Errorf("parse proxy URL: %w", err)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https", "socks5":
	default:
		return nil, fmt.Errorf("proxy URL scheme %q must be http, https, or socks5", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("proxy URL requires a host")
	}
	return http.ProxyURL(u), nil
}
