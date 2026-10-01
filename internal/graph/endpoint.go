package graph

import (
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// TargetType distinguishes a DNS name from an IP without resolving either.
type TargetType string

const (
	DNSTarget TargetType = "dns"
	IPTarget  TargetType = "ip"
)

// Target is a canonical observed address, not an authoritative machine.
type Target struct {
	typ   TargetType
	value string
}

func (t Target) Type() TargetType { return t.typ }
func (t Target) Value() string    { return t.value }

// ParseTarget accepts a bare DNS name or IP literal (optionally bracketed IPv6).
// DNS input must be ASCII; callers must convert international names to A-labels.
func ParseTarget(raw string) (Target, error) {
	if strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]") {
		ip, err := netip.ParseAddr(raw[1 : len(raw)-1])
		if err != nil || !ip.Is6() || ip.Zone() != "" {
			return Target{}, errors.New("invalid bracketed IP target")
		}
		return Target{IPTarget, ip.String()}, nil
	}
	if ip, err := netip.ParseAddr(raw); err == nil {
		if ip.Zone() != "" {
			return Target{}, errors.New("zoned IP targets are not supported")
		}
		return Target{IPTarget, ip.String()}, nil
	}
	// Reject non-ASCII before case folding: Unicode characters such as the
	// Kelvin sign fold to ASCII and must not silently become another hostname.
	for _, c := range raw {
		if c > 127 {
			return Target{}, errors.New("target hostname must be ASCII DNS labels")
		}
	}
	host := strings.ToLower(strings.TrimSuffix(raw, "."))
	if len(host) == 0 || len(host) > 253 {
		return Target{}, errors.New("invalid target hostname")
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return Target{}, errors.New("invalid target hostname label")
		}
		for _, c := range label {
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return Target{}, errors.New("target hostname must be ASCII DNS labels")
			}
		}
	}
	// Do not silently reinterpret a malformed numeric address as DNS.
	if tld := host[strings.LastIndexByte(host, '.')+1:]; strings.HasPrefix(tld, "0x") || strings.Trim(tld, "0123456789") == "" {
		return Target{}, errors.New("invalid numeric IP target")
	}
	return Target{DNSTarget, host}, nil
}

// Endpoint is an immutable canonical HTTP(S) service endpoint. String omits the
// instance key as well as all excluded query material.
type Endpoint struct {
	scheme      string
	host        string
	port        uint16
	basePath    string
	instanceKey string
}

func (e Endpoint) Scheme() string      { return e.scheme }
func (e Endpoint) Host() string        { return e.host }
func (e Endpoint) Port() uint16        { return e.port }
func (e Endpoint) BasePath() string    { return e.basePath }
func (e Endpoint) InstanceKey() string { return e.instanceKey }
func (e Endpoint) String() string {
	if e.scheme == "" {
		return ""
	}
	return e.scheme + "://" + net.JoinHostPort(e.host, strconv.Itoa(int(e.port))) + e.basePath
}

// ParseEndpoint never resolves DNS or follows redirects. Root and empty paths
// are equivalent; non-root slash/dot/path distinctions are preserved. Queries
// require a stable, non-secret configured instance key and are not retained.
// Userinfo and fragments are rejected. Errors never echo raw URL material.
func ParseEndpoint(raw, instanceKey string) (Endpoint, error) {
	if instanceKey != "" && !validStableText(instanceKey) {
		return Endpoint{}, errors.New("invalid endpoint instance key")
	}
	for _, c := range raw {
		if c <= ' ' || c == 127 {
			return Endpoint{}, errors.New("invalid whitespace or control in endpoint")
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return Endpoint{}, errors.New("malformed endpoint URL")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return Endpoint{}, errors.New("endpoint must use HTTP or HTTPS")
	}
	if u.Opaque != "" || u.Host == "" || u.User != nil || strings.Contains(raw, "#") {
		return Endpoint{}, errors.New("endpoint requires authority without credentials or fragment")
	}
	if (u.RawQuery != "" || u.ForceQuery) && instanceKey == "" {
		return Endpoint{}, errors.New("query-bearing endpoint requires a non-secret instance key")
	}
	// url.Parse permits an empty port and an unbracketed IPv6 authority.
	if strings.HasSuffix(u.Host, ":") || (!strings.HasPrefix(u.Host, "[") && strings.Count(u.Host, ":") > 1) {
		return Endpoint{}, errors.New("invalid endpoint authority")
	}
	target, err := ParseTarget(u.Hostname())
	if err != nil {
		return Endpoint{}, errors.New("invalid endpoint host")
	}
	if strings.HasPrefix(u.Host, "[") && target.typ != IPTarget {
		return Endpoint{}, errors.New("brackets require an IP literal")
	}
	port := uint64(80)
	if scheme == "https" {
		port = 443
	}
	if u.Port() != "" {
		port, err = strconv.ParseUint(u.Port(), 10, 16)
		if err != nil || port == 0 {
			return Endpoint{}, errors.New("invalid endpoint port")
		}
	}
	for _, c := range u.Path {
		if c < ' ' || c == 127 {
			return Endpoint{}, errors.New("control character in endpoint path")
		}
	}
	path := canonicalEscapes(u.EscapedPath())
	if path == "" {
		path = "/"
	}
	return Endpoint{scheme, target.value, uint16(port), path, instanceKey}, nil
}

func canonicalEscapes(path string) string {
	var b strings.Builder
	for i := 0; i < len(path); i++ {
		if path[i] != '%' {
			b.WriteByte(path[i])
			continue
		}
		// EscapedPath has already validated escapes.
		v, _ := strconv.ParseUint(path[i+1:i+3], 16, 8)
		c := byte(v)
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.ContainsRune("-._~", rune(c)) {
			b.WriteByte(c)
		} else {
			const hex = "0123456789ABCDEF"
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&15])
		}
		i += 2
	}
	return b.String()
}
