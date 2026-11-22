// Package common provides shared collector helpers for target parsing,
// transport handling, access summarization, graph attachment, evidence
// emission, and bounded text sanitization.
package common

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/0x3df/LLMHound/internal/config"
	"github.com/0x3df/LLMHound/internal/content"
	"github.com/0x3df/LLMHound/internal/correlate"
	"github.com/0x3df/LLMHound/internal/emitter"
	"github.com/0x3df/LLMHound/internal/evidence"
	"github.com/0x3df/LLMHound/internal/graph"
	"github.com/0x3df/LLMHound/internal/transport"
)

var (
	urlInErrorRE   = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^\s"'<>]+`)
	cleanVersionRE = regexp.MustCompile(`^[0-9]+(\.[0-9]+){1,3}([.-][0-9A-Za-z.-]+)?$`)
)

// ParseTargetEndpoint normalizes a target string (host, IP, host:port, or URL)
// into a canonical graph.Endpoint using defaultPort when omitted on bare targets.
func ParseTargetEndpoint(rawTarget string, defaultPort int) (graph.Endpoint, string, error) {
	trimmed := strings.TrimSpace(rawTarget)
	if trimmed == "" {
		return graph.Endpoint{}, "", errors.New("empty target")
	}

	rawURL := trimmed
	if !strings.Contains(rawURL, "://") {
		hostPart, pathPart, hasPath := strings.Cut(rawURL, "/")
		portStr := strconv.Itoa(defaultPort)
		switch {
		case isBareIPv6(hostPart):
			ipStr := strings.TrimSuffix(strings.TrimPrefix(hostPart, "["), "]")
			hostPart = net.JoinHostPort(ipStr, portStr)
		default:
			if ip, err := netip.ParseAddr(hostPart); err == nil {
				hostPart = net.JoinHostPort(ip.String(), portStr)
			} else if _, _, err := net.SplitHostPort(hostPart); err != nil {
				hostPart = net.JoinHostPort(hostPart, portStr)
			}
		}
		if hasPath {
			rawURL = "http://" + hostPart + "/" + pathPart
		} else {
			rawURL = "http://" + hostPart
		}
	}

	ep, err := graph.ParseEndpoint(rawURL, "")
	if err != nil {
		return graph.Endpoint{}, "", fmt.Errorf("parse target endpoint %q: %w", evidence.SanitizeURL(trimmed), err)
	}
	return ep, ep.Host(), nil
}

func isBareIPv6(s string) bool {
	if !strings.HasPrefix(s, "[") || !strings.HasSuffix(s, "]") {
		return false
	}
	ip, err := netip.ParseAddr(s[1 : len(s)-1])
	return err == nil && ip.Is6()
}

// NewTransportClient builds a transport.Client enforcing collection safety bounds.
func NewTransportClient(cfg config.Config) *transport.Client {
	return transport.NewClient(transport.Config{
		Bounds:          cfg.Bounds,
		Insecure:        cfg.Insecure,
		UserAgent:       cfg.UserAgent,
		AuthorizedHosts: cfg.Targets,
	})
}

// EvidenceID returns a deterministic evidence ID prefix for a service observation.
func EvidenceID(scanID, serviceID string, obsTime time.Time) string {
	raw := scanID + "|" + serviceID + "|" + obsTime.UTC().Format(time.RFC3339Nano)
	sum := sha256.Sum256([]byte(raw))
	return "ev-" + hex.EncodeToString(sum[:8])
}

// AbsorbTransport preserves the first observed TLS summary and appends any redirects.
func AbsorbTransport(resp *transport.Response, tlsInfo **transport.TLSInfo, redirects *[]transport.RedirectInfo) {
	if resp == nil {
		return
	}
	if tlsInfo != nil && *tlsInfo == nil && resp.TLS != nil {
		*tlsInfo = resp.TLS
	}
	if redirects != nil && len(resp.Redirects) > 0 {
		*redirects = append(*redirects, resp.Redirects...)
	}
}

// IsTLSFailure reports whether TLS verification failed without an insecure override.
func IsTLSFailure(tlsInfo *transport.TLSInfo, insecure bool) bool {
	return !insecure && tlsInfo != nil && tlsInfo.VerificationResult == "failed"
}

// TLSSummary converts a transport.TLSInfo to a graph.TLSSummary.
func TLSSummary(info *transport.TLSInfo) *graph.TLSSummary {
	if info == nil {
		return nil
	}
	return &graph.TLSSummary{
		Result:      info.VerificationResult,
		Reason:      info.VerificationReason,
		LeafSHA256:  info.CertFingerprint,
		Issuer:      info.Issuer,
		NotAfter:    info.ValidTo,
		TLSVersion:  info.NegotiatedVersion,
		InsecureSet: info.InsecureOverride,
	}
}

// CheckEntry describes one allowlisted check outcome for access summarization
// and sidecar emission.
type CheckEntry struct {
	CheckID        string
	Operation      string
	Outcome        graph.Outcome
	Reason         string
	Anonymous      bool
	OperationKind  graph.OperationKind
	CountForAccess bool
	Details        map[string]any
}

// SummarizeAccess derives flat service access properties from enumeration checks.
// Version-only or content-tier checks set CountForAccess=false so they never
// populate anon_operations, while denials on any endpoint still record auth_observed.
func SummarizeAccess(srvID string, obs graph.Observation, checks []CheckEntry) graph.Access {
	var ev []graph.AccessEvidence
	for _, ch := range checks {
		if (ch.CountForAccess && ch.Anonymous && ch.Outcome == graph.OutcomeSuccess) || ch.Outcome == graph.OutcomeDenied {
			ev = append(ev, graph.AccessEvidence{
				Observation:   obs,
				CheckID:       ch.CheckID,
				Operation:     ch.Operation,
				TargetID:      srvID,
				Outcome:       ch.Outcome,
				Reason:        ch.Reason,
				Anonymous:     ch.Anonymous && ch.Outcome == graph.OutcomeSuccess,
				OperationKind: ch.OperationKind,
			})
		}
	}
	return graph.SummarizeAccess(ev)
}

// AttachService emits an ObservedAt edge to the mapped native node or a scoped
// NetworkEndpoint fallback node, plus a correlation evidence record.
func AttachService(
	scope, targetHost string,
	srvID graph.Identity,
	obs, corrObs graph.Observation,
	resolver *correlate.Resolver,
) (graph.Edge, *emitter.NodeItem, evidence.Record, error) {
	corrRes, err := resolver.Resolve(scope, targetHost)
	if err != nil {
		return graph.Edge{}, nil, evidence.Record{}, fmt.Errorf("correlate target: %w", err)
	}
	edge, err := corrRes.ObservedAt(srvID, obs)
	if err != nil {
		return graph.Edge{}, nil, evidence.Record{}, fmt.Errorf("create ObservedAt edge: %w", err)
	}

	var fallbackItem *emitter.NodeItem
	if fbID, ok := corrRes.FallbackIdentity(); ok {
		netNode, err := graph.NewNode(fbID, obs)
		if err != nil {
			return graph.Edge{}, nil, evidence.Record{}, fmt.Errorf("create fallback node: %w", err)
		}
		ev := corrRes.Evidence()
		item, err := emitter.NewNodeItem(netNode, map[string]any{
			"name":         strings.ToUpper(ev.NormalizedTarget),
			"target_type":  string(ev.TargetType),
			"target_value": ev.NormalizedTarget,
		})
		if err != nil {
			return graph.Edge{}, nil, evidence.Record{}, fmt.Errorf("create fallback node item: %w", err)
		}
		fallbackItem = &item
	}

	corrRec, err := evidence.NewCorrelationRecord(corrRes.Evidence(), corrObs)
	if err != nil {
		return graph.Edge{}, nil, evidence.Record{}, fmt.Errorf("create correlation record: %w", err)
	}
	return edge, fallbackItem, corrRec, nil
}

// BuildEvidenceRecords constructs sidecar records for checks, fingerprint, TLS,
// redirects, and correlation.
func BuildEvidenceRecords(
	srvID string,
	obs graph.Observation,
	evPrefix string,
	checks []CheckEntry,
	fp *evidence.FingerprintInput,
	tlsInfo *transport.TLSInfo,
	redirects []transport.RedirectInfo,
	corrRec *evidence.Record,
) ([]evidence.Record, error) {
	records := make([]evidence.Record, 0, len(checks)+len(redirects)+3)

	for _, ch := range checks {
		chkObs := obs
		chkObs.EvidenceID = evPrefix + "-" + ch.CheckID
		if ch.Anonymous && ch.Outcome == graph.OutcomeSuccess {
			rec, err := evidence.NewAccessEvidenceRecord(graph.AccessEvidence{
				Observation:   chkObs,
				CheckID:       ch.CheckID,
				Operation:     ch.Operation,
				TargetID:      srvID,
				Outcome:       ch.Outcome,
				Reason:        ch.Reason,
				Anonymous:     true,
				OperationKind: ch.OperationKind,
			}, ch.Details)
			if err != nil {
				return nil, fmt.Errorf("create access evidence record %s: %w", ch.CheckID, err)
			}
			records = append(records, rec)
			continue
		}
		rec, err := evidence.NewCheckResultRecord(graph.CheckResult{
			Observation: chkObs,
			CheckID:     ch.CheckID,
			Operation:   ch.Operation,
			TargetID:    srvID,
			Outcome:     ch.Outcome,
			Reason:      ch.Reason,
		}, ch.Details)
		if err != nil {
			return nil, fmt.Errorf("create check result record %s: %w", ch.CheckID, err)
		}
		records = append(records, rec)
	}

	if fp != nil {
		fpCopy := *fp
		fpCopy.Observation = obs
		fpCopy.Observation.EvidenceID = evPrefix + "-fingerprint"
		rec, err := evidence.NewFingerprintRecord(fpCopy)
		if err != nil {
			return nil, fmt.Errorf("create fingerprint record: %w", err)
		}
		records = append(records, rec)
	}

	if tlsInfo != nil {
		tlsObs := obs
		tlsObs.EvidenceID = evPrefix + "-tls"
		rec, err := evidence.NewTLSRecord(evidence.TLSRecordInput{
			Observation:        tlsObs,
			TargetID:           srvID,
			CertFingerprint:    tlsInfo.CertFingerprint,
			Issuer:             tlsInfo.Issuer,
			Subject:            tlsInfo.Subject,
			SANs:               tlsInfo.SANs,
			ValidFrom:          tlsInfo.ValidFrom,
			ValidTo:            tlsInfo.ValidTo,
			VerificationResult: tlsInfo.VerificationResult,
			VerificationReason: tlsInfo.VerificationReason,
			NegotiatedVersion:  tlsInfo.NegotiatedVersion,
			InsecureOverride:   tlsInfo.InsecureOverride,
		})
		if err != nil {
			return nil, fmt.Errorf("create tls record: %w", err)
		}
		records = append(records, rec)
	}

	for i, red := range redirects {
		redObs := obs
		redObs.EvidenceID = fmt.Sprintf("%s-redirect-%d", evPrefix, i)
		rec, err := evidence.NewRedirectRecord(evidence.RedirectRecordInput{
			Observation: redObs,
			FromURL:     red.FromURL,
			ToURL:       red.ToURL,
			StatusCode:  red.StatusCode,
			Authorized:  red.Authorized,
			Reason:      red.Reason,
		})
		if err != nil {
			return nil, fmt.Errorf("create redirect record %d: %w", i, err)
		}
		records = append(records, rec)
	}

	if corrRec != nil {
		records = append(records, *corrRec)
	}

	return records, nil
}

// SanitizeError strips URL credentials, queries, fragments, and control chars
// from an error string and bounds it to 256 bytes.
func SanitizeError(err error) string {
	if err == nil {
		return ""
	}
	msg := urlInErrorRE.ReplaceAllStringFunc(err.Error(), evidence.SanitizeURL)
	return BoundString(msg, 256)
}

// SanitizeHTTPReference validates and strips userinfo, query parameters, and
// fragments from an advertised HTTP/HTTPS reference URL.
func SanitizeHTTPReference(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || strings.ContainsFunc(trimmed, unicode.IsControl) {
		return ""
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	if (scheme != "http" && scheme != "https") || u.Host == "" || u.Hostname() == "" {
		return ""
	}
	u.Scheme = scheme
	u.User = nil
	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	return u.String()
}

// NormalizeVersion normalizes unambiguous dotted numeric versions (with optional
// leading v/V). Ambiguous strings return empty string so unknown stays unknown.
func NormalizeVersion(raw string) string {
	s := strings.TrimSpace(raw)
	s = strings.TrimPrefix(s, "v")
	s = strings.TrimPrefix(s, "V")
	s = strings.TrimSpace(s)
	if !cleanVersionRE.MatchString(s) {
		return ""
	}
	return s
}

// BoundString strips control characters and bounds s to maxLen bytes without
// splitting UTF-8 runes, appending "…[truncated]" when shortened.
func BoundString(s string, maxLen int) string {
	cleaned := strings.Map(func(r rune) rune {
		switch r {
		case '\r', '\n', '\t':
			return ' '
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	cleaned = strings.TrimSpace(cleaned)
	if maxLen > 0 && len(cleaned) > maxLen {
		cut := maxLen
		for cut > 0 && !utf8.RuneStart(cleaned[cut]) {
			cut--
		}
		return strings.TrimRight(cleaned[:cut], " ") + "…[truncated]"
	}
	return cleaned
}

// ContentSummaryFromBudget builds a graph.ContentSummary from a content.Budget.
func ContentSummaryFromBudget(budget *content.Budget, obsTime time.Time, sysPrompt, cfgCollected *bool) *graph.ContentSummary {
	if budget == nil {
		return nil
	}
	return &graph.ContentSummary{
		Collected:           true,
		Bytes:               budget.Bytes(),
		Truncated:           budget.Truncated(),
		SystemPromptPresent: sysPrompt,
		ConfigCollected:     cfgCollected,
		SecretTypes:         budget.SecretTypes(),
		SecretConfirmedAt:   obsTime,
		ExposedAZAppIDs:     budget.ExposedAZAppIDs(),
		ExposedAWSKeyIDs:    budget.ExposedAWSKeyIDs(),
		ExposedPubKeySHA256: budget.ExposedPubKeySHA256(),
	}
}

// IntPtr returns a pointer to n for optional inventory counts.
func IntPtr(n int) *int {
	return &n
}
