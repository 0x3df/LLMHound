package common

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/0x3df/LLMHound/internal/transport"
)

var (
	entraURLRe            = regexp.MustCompile(`https?://(?:login\.microsoftonline\.(?:com|us)|login\.chinacloudapi\.cn|sts\.windows\.net)[^\s"'<>]*`)
	entraUUIDRe           = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	entraExplicitClientRe = regexp.MustCompile(`(?i)(?:microsoft|entra|azure)[_-]?client[_-]?id["']?\s*[:=]\s*["']?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})["']?`)
	entraExplicitTenantRe = regexp.MustCompile(`(?i)(?:microsoft|entra|azure)[_-]?tenant[_-]?id["']?\s*[:=]\s*["']?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})["']?`)
	genericClientIDJSONRe = regexp.MustCompile(`(?i)"client_?id"\s*:\s*"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"`)
)

// ExtractEntraOIDC passively extracts Microsoft Entra ID tenant_id (lowercase UUID)
// and client_id (uppercase UUID) from anonymous HTTP responses, OAuth metadata,
// WWW-Authenticate headers, and login redirect URLs.
func ExtractEntraOIDC(inputs ...string) (tenantID, clientID string) {
	for _, raw := range inputs {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		for _, match := range entraURLRe.FindAllString(raw, -1) {
			t, c := parseEntraURL(match)
			if tenantID == "" && t != "" {
				tenantID = t
			}
			if clientID == "" && c != "" {
				clientID = c
			}
		}
		if m := entraExplicitTenantRe.FindStringSubmatch(raw); len(m) == 2 && tenantID == "" {
			if u := normalizeUUID(m[1], false); u != "" {
				tenantID = u
			}
		}
		if m := entraExplicitClientRe.FindStringSubmatch(raw); len(m) == 2 && clientID == "" {
			if u := normalizeUUID(m[1], true); u != "" {
				clientID = u
			}
		}
		// Only accept generic "client_id" in JSON when an Entra authority URL is
		// present in the same input and no competing non-Microsoft OAuth provider
		// URLs muddy which client_id belongs to Entra.
		if clientID == "" && entraURLRe.MatchString(raw) {
			lower := strings.ToLower(raw)
			if !strings.Contains(lower, "accounts.google.com") && !strings.Contains(lower, "github.com/login") {
				if m := genericClientIDJSONRe.FindStringSubmatch(raw); len(m) == 2 {
					if u := normalizeUUID(m[1], true); u != "" {
						clientID = u
					}
				}
			}
		}
		if tenantID != "" && clientID != "" {
			break
		}
	}
	return tenantID, clientID
}

// ExtractEntraFromHeaders inspects response Location and Www-Authenticate headers.
func ExtractEntraFromHeaders(h http.Header) (tenantID, clientID string) {
	if len(h) == 0 {
		return "", ""
	}
	var inputs []string
	for _, k := range []string{"Location", "Www-Authenticate"} {
		inputs = append(inputs, h.Values(k)...)
	}
	return ExtractEntraOIDC(inputs...)
}

// ExtractEntraFromRedirects inspects recorded redirect hops for Entra authorization endpoints.
func ExtractEntraFromRedirects(redirects []transport.RedirectInfo) (tenantID, clientID string) {
	if len(redirects) == 0 {
		return "", ""
	}
	inputs := make([]string, 0, len(redirects)*2)
	for _, r := range redirects {
		inputs = append(inputs, r.FromURL, r.ToURL)
	}
	return ExtractEntraOIDC(inputs...)
}

func parseEntraURL(rawURL string) (tenantID, clientID string) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", ""
	}
	host := strings.ToLower(u.Hostname())
	switch host {
	case "login.microsoftonline.com", "login.microsoftonline.us", "login.chinacloudapi.cn", "sts.windows.net":
	default:
		return "", ""
	}
	segs := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(segs) > 0 {
		tenantID = normalizeUUID(segs[0], false)
	}
	if qClient := strings.TrimSpace(u.Query().Get("client_id")); qClient != "" {
		clientID = normalizeUUID(qClient, true)
	}
	return tenantID, clientID
}

func normalizeUUID(s string, upper bool) string {
	s = strings.TrimSpace(s)
	if !entraUUIDRe.MatchString(s) {
		return ""
	}
	stripped := strings.ReplaceAll(strings.ToLower(s), "-", "")
	if strings.Count(stripped, "0") == 32 || strings.Count(stripped, "f") == 32 {
		return ""
	}
	if upper {
		return strings.ToUpper(s)
	}
	return strings.ToLower(s)
}
