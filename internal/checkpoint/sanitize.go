package checkpoint

import (
	"encoding/json"
	"net/url"
	"strings"

	"github.com/0x3df/LLMHound/internal/evidence"
)

const (
	DefaultMaxStringSize = 4096
	DefaultMaxEntryBytes = 1024 * 1024 // 1 MB
	TruncatedSuffix      = "…[truncated]"
	RedactedPlaceholder  = "[REDACTED]"
)

var sensitiveKeyFragments = []string{
	"authorization",
	"cookie",
	"api_key",
	"api-key",
	"apikey",
	"passw",
	"passwd",
	"secret",
	"bearer",
	"credential",
	"private_key",
	"client_secret",
}

// isSensitiveKey checks if a property or detail key is sensitive and must be redacted.
func isSensitiveKey(key string) bool {
	lower := strings.ToLower(key)
	if lower == "auth" || strings.HasSuffix(lower, "token") || strings.Contains(lower, "token") {
		return true
	}
	for _, f := range sensitiveKeyFragments {
		if strings.Contains(lower, f) {
			return true
		}
	}
	return false
}

// boundString truncates strings exceeding maxLen and appends TruncatedSuffix.
func boundString(s string, maxLen int) string {
	if maxLen <= 0 {
		maxLen = DefaultMaxStringSize
	}
	if len(s) > maxLen {
		return s[:maxLen] + TruncatedSuffix
	}
	return s
}

// SanitizeTarget strips userinfo, credentials, query parameters, and fragments from target strings.
func SanitizeTarget(raw string) string {
	if raw == "" {
		return ""
	}
	// If it parses as a URL with a scheme, sanitize via evidence.SanitizeURL
	if strings.Contains(raw, "://") {
		return evidence.SanitizeURL(raw)
	}
	// Bare target like user:pass@host:port or host:port
	if strings.Contains(raw, "@") {
		parts := strings.SplitN(raw, "@", 2)
		return parts[1]
	}
	return raw
}

// SanitizeURL strips credentials, query strings, and fragments.
func SanitizeURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "[malformed_url]"
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

// SanitizeMap recursively redacts sensitive keys and bounds string values in a map.
func SanitizeMap(m map[string]any, maxStringLen int) map[string]any {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		if isSensitiveKey(k) {
			out[k] = RedactedPlaceholder
			continue
		}
		out[k] = sanitizeValue(v, maxStringLen)
	}
	return out
}

func sanitizeValue(v any, maxStringLen int) any {
	switch t := v.(type) {
	case nil, bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64, json.Number:
		return t
	case string:
		return boundString(t, maxStringLen)
	case map[string]any:
		return SanitizeMap(t, maxStringLen)
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = sanitizeValue(e, maxStringLen)
		}
		return out
	case []string:
		out := make([]string, len(t))
		for i, s := range t {
			out[i] = boundString(s, maxStringLen)
		}
		return out
	default:
		raw, err := json.Marshal(t)
		if err != nil {
			return "[unserializable]"
		}
		var normalized any
		if err := json.Unmarshal(raw, &normalized); err != nil {
			return "[unserializable]"
		}
		return sanitizeValue(normalized, maxStringLen)
	}
}
