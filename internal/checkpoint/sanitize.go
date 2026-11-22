package checkpoint

import (
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/0x3df/LLMHound/internal/config"
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
	"secret",
	"bearer",
	"credential",
	"private_key",
	"client_secret",
}

var classificationKeys = map[string]bool{
	"has_exposed_secret":    true,
	"secret_types":          true,
	"secret_last_confirmed": true,
}

// isSensitiveKey checks if a property or detail key is sensitive and must be redacted.
func isSensitiveKey(key string) bool {
	lower := strings.ToLower(key)
	if lower == "auth" || strings.HasSuffix(lower, "token") {
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
		cut := maxLen
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		return s[:cut] + TruncatedSuffix
	}
	return s
}

var (
	urlInTextPattern    = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^\s"'<>]+`)
	bearerInTextPattern = regexp.MustCompile(`(?i)\b(bearer|basic)\s+[^\s"']+`)
	secretInTextPattern = regexp.MustCompile(`(?i)\b([a-z_-]*(?:token|passw[a-z]*|secret|api[_-]?key))\s*[=:]\s*[^\s"'&,;]+`)
)

// sanitizeText strips credentials and URL query data embedded in free text, then bounds it.
func sanitizeText(s string, maxLen int) string {
	s = urlInTextPattern.ReplaceAllStringFunc(s, SanitizeURL)
	s = bearerInTextPattern.ReplaceAllString(s, "${1} "+RedactedPlaceholder)
	s = secretInTextPattern.ReplaceAllString(s, "${1}="+RedactedPlaceholder)
	return boundString(s, maxLen)
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
	if idx := strings.LastIndex(raw, "@"); idx >= 0 {
		return raw[idx+1:]
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
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		if classificationKeys[k] {
			if safe, ok := sanitizeClassificationValue(k, v); ok {
				out[k] = safe
			}
			continue
		}
		if isSensitiveKey(k) {
			out[k] = RedactedPlaceholder
			continue
		}
		out[k] = sanitizeValue(v, maxStringLen)
	}
	return out
}

// sanitizeClassificationValue accepts only the canonical value shape of a
// graph-model classification property. Invalid values are omitted so arbitrary
// collector detail text cannot cross the sensitive-key sanitizer by using a
// reserved property name.
func sanitizeClassificationValue(key string, value any) (any, bool) {
	switch key {
	case "has_exposed_secret":
		v, ok := value.(bool)
		return true, ok && v
	case "secret_types":
		var raw []string
		switch values := value.(type) {
		case []string:
			raw = values
		case []any:
			raw = make([]string, 0, len(values))
			for _, value := range values {
				s, ok := value.(string)
				if !ok {
					return nil, false
				}
				raw = append(raw, s)
			}
		default:
			return nil, false
		}
		if len(raw) == 0 {
			return nil, false
		}
		seen := make(map[string]bool, len(raw))
		out := make([]string, 0, len(raw))
		for _, typ := range raw {
			if !config.IsKnownSecretDetector(typ) {
				return nil, false
			}
			if !seen[typ] {
				seen[typ] = true
				out = append(out, typ)
			}
		}
		sort.Strings(out)
		return out, true
	case "secret_last_confirmed":
		s, ok := value.(string)
		if !ok {
			return nil, false
		}
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return nil, false
		}
		_, offset := t.Zone()
		if offset != 0 {
			return nil, false
		}
		return t.UTC().Format(time.RFC3339), true
	default:
		return nil, false
	}
}

func sanitizeValue(v any, maxStringLen int) any {
	switch t := v.(type) {
	case nil, bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64, json.Number:
		return t
	case string:
		return sanitizeText(t, maxStringLen)
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
			out[i] = sanitizeText(s, maxStringLen)
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
