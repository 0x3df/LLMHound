package secrets

import (
	"regexp"
	"strings"
)

const azureClientSecretName = "azure_client_secret"

// azureUUIDRe matches canonical 8-4-4-4-12 UUIDs used for Entra client IDs.
var azureUUIDRe = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)

// azureV2SecretRe matches modern Microsoft Entra ID v2 client secret values
// carrying the structural "8Q~" marker (typically 40 chars).
var azureV2SecretRe = regexp.MustCompile(`[A-Za-z0-9_.-]{3}8Q~[A-Za-z0-9._~-]{30,36}[A-Za-z0-9_~]`)

// azureLabeledSecretRe matches explicitly named Azure/Entra client secret
// assignments for legacy or custom-secret test/prod configs without 8Q~.
var azureLabeledSecretRe = regexp.MustCompile(`(?i)\b(?:azure|entra|microsoft)[_-]?client[_-]?secret\b\s*[:=]\s*["']?([A-Za-z0-9._~-]{32,48})["']?`)

type azureDetector struct{}

func newAzureDetector() Detector { return azureDetector{} }

func (azureDetector) Name() string { return azureClientSecretName }

// Find reports an azure_client_secret match only when a verified client secret
// pairs within 512 bytes with an explicitly labeled client/app UUID (never a
// tenant/subscription/object UUID). Only the secret value is redacted; the public
// AZApp client UUID is recorded on Finding.PrincipalID.
func (azureDetector) Find(body string) []Match {
	clientIDs := extractAzureClientIDs(body)
	if len(clientIDs) == 0 {
		return nil
	}

	cands := extractAzureSecretCandidates(body)
	if len(cands) == 0 {
		return nil
	}

	const maxPairDistance = 512
	used := make([]bool, len(cands))
	var matches []Match
	for _, cid := range clientIDs {
		best, bestDist := -1, maxPairDistance+1
		for i, c := range cands {
			if used[i] {
				continue
			}
			d := cid.start - c.Start
			if d < 0 {
				d = c.Start - cid.end
			}
			if d <= maxPairDistance && d < bestDist {
				best, bestDist = i, d
			}
		}
		if best < 0 {
			continue
		}
		used[best] = true
		matches = append(matches, Match{
			Type:          azureClientSecretName,
			Spans:         []Span{cands[best]},
			PrincipalKind: "AZApp",
			PrincipalID:   strings.ToUpper(cid.uuid),
		})
	}
	return matches
}

type azureClientIDMatch struct {
	start int
	end   int
	uuid  string
}

func extractAzureClientIDs(body string) []azureClientIDMatch {
	var out []azureClientIDMatch
	for _, loc := range azureUUIDRe.FindAllStringIndex(body, -1) {
		if loc[0] > 0 && isWordByte(body[loc[0]-1]) {
			continue
		}
		if loc[1] < len(body) && isWordByte(body[loc[1]]) {
			continue
		}
		prefixStart := loc[0] - 64
		if prefixStart < 0 {
			prefixStart = 0
		}
		// Inspect only text since the previous newline/delimiter to avoid picking
		// up an unrelated key from an earlier line.
		ctx := body[prefixStart:loc[0]]
		if nl := strings.LastIndexAny(ctx, "\n\r;,"); nl >= 0 {
			ctx = ctx[nl+1:]
		}
		lower := strings.ToLower(ctx)
		if !(strings.Contains(lower, "client_id") ||
			strings.Contains(lower, "clientid") ||
			strings.Contains(lower, "client-id") ||
			strings.Contains(lower, "app_id") ||
			strings.Contains(lower, "appid") ||
			strings.Contains(lower, "app-id")) {
			continue
		}
		if strings.Contains(lower, "tenant") ||
			strings.Contains(lower, "subscription") ||
			strings.Contains(lower, "object_id") ||
			strings.Contains(lower, "objectid") {
			continue
		}
		val := body[loc[0]:loc[1]]
		if isPlaceholderUUID(val) {
			continue
		}
		out = append(out, azureClientIDMatch{start: loc[0], end: loc[1], uuid: val})
	}
	return out
}

func extractAzureSecretCandidates(body string) []Span {
	var cands []Span
	seen := make(map[int]bool)

	addIfValid := func(start, end int) {
		if seen[start] {
			return
		}
		if !azureSecretBoundary(body, start, end) {
			return
		}
		val := body[start:end]
		if azureUUIDRe.MatchString(val) || !hasUpperLowerDigit(val) || isPlaceholder(val) || isKnownExample(tokenDigest(val)) {
			return
		}
		seen[start] = true
		cands = append(cands, Span{Start: start, End: end})
	}

	for _, loc := range azureV2SecretRe.FindAllStringIndex(body, -1) {
		addIfValid(loc[0], loc[1])
	}
	for _, sub := range azureLabeledSecretRe.FindAllStringSubmatchIndex(body, -1) {
		if len(sub) >= 4 && sub[2] >= 0 && sub[3] > sub[2] {
			addIfValid(sub[2], sub[3])
		}
	}
	return cands
}

func azureSecretBoundary(body string, start, end int) bool {
	if start > 0 && isAzureSecretExtender(body[start-1]) {
		return false
	}
	return end >= len(body) || !isAzureSecretExtender(body[end])
}

func isAzureSecretExtender(c byte) bool {
	return isWordByte(c) || c == '~'
}

func isPlaceholderUUID(u string) bool {
	stripped := strings.ReplaceAll(strings.ToLower(u), "-", "")
	if len(stripped) != 32 {
		return true
	}
	allZero := strings.Count(stripped, "0") == 32
	allF := strings.Count(stripped, "f") == 32
	return allZero || allF
}
