// Package secrets implements high-precision, structure-verified secret
// detectors run over content-tier bodies. A detector only reports a match
// when the format is fully verified (checksum, parse, or pairing rule), so a
// hit is deterministic evidence; look-alike text must never match. Values are
// never stored: the redactor returns byte spans and the caller replaces each
// span with a [secret:<type>] marker (docs/02-graph-model.md#content-and-secrets).
package secrets

import (
	"sort"
	"strings"

	"github.com/0x3df/LLMHound/internal/config"
	"github.com/0x3df/LLMHound/internal/content"
)

// Span is a half-open [Start, End) byte range into the original body.
type Span struct {
	Start int
	End   int // exclusive
}

// Match is one verified secret: the detector type and every span holding
// secret material (an AWS pair has two).
type Match struct {
	Type  string
	Spans []Span
}

// Detector scans one body for secrets of a single type.
type Detector interface {
	Name() string
	Find(body string) []Match
}

// Detectors returns every built-in detector, sorted by name.
func Detectors() []Detector {
	return []Detector{
		newAWSDetector(),
		newGitHubDetector(),
		newPrivateKeyDetector(),
	}
}

// NewRedactor builds the content.Redactor that runs every enabled detector
// over a body, replaces secret spans with [secret:<type>] markers, and returns
// one Finding per match. It returns nil when every detector is disabled, so
// collectors can skip the hook entirely.
func NewRedactor(cfg config.Secrets) content.Redactor {
	var enabled []Detector
	for _, d := range Detectors() {
		if cfg.DetectorEnabled(d.Name()) {
			enabled = append(enabled, d)
		}
	}
	if len(enabled) == 0 {
		return nil
	}
	return func(body string) (string, []content.Finding) {
		return redact(body, enabled)
	}
}

// redact runs every detector, records one Finding per match (line counted on
// the original body), and rebuilds the body with merged [secret:<type>]
// markers. Exposed for tests so synthetic overlapping matches can exercise
// the shared path.
func redact(body string, enabled []Detector) (string, []content.Finding) {
	var findings []content.Finding
	var matches []Match
	for _, d := range enabled {
		for _, m := range d.Find(body) {
			if len(m.Spans) == 0 {
				continue
			}
			findings = append(findings, content.Finding{
				Type: m.Type,
				Line: 1 + strings.Count(body[:m.Spans[0].Start], "\n"),
			})
			matches = append(matches, m)
		}
	}
	return redactMatches(body, matches), findings
}

type typedSpan struct {
	span Span
	typ  string
}

// redactMatches merges every match's spans and rebuilds the body with
// [secret:<type>] markers. A merged span is the union of overlapping or
// adjacent spans and carries the type of the earliest-starting span.
func redactMatches(body string, matches []Match) string {
	var spans []typedSpan
	for _, m := range matches {
		for _, s := range m.Spans {
			spans = append(spans, typedSpan{span: s, typ: m.Type})
		}
	}
	if len(spans) == 0 {
		return body
	}
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].span.Start != spans[j].span.Start {
			return spans[i].span.Start < spans[j].span.Start
		}
		// Same start: longer span first so it becomes the merged marker type.
		if len2(spans[i].span) != len2(spans[j].span) {
			return len2(spans[i].span) > len2(spans[j].span)
		}
		return spans[i].typ < spans[j].typ
	})
	merged := spans[:1]
	for _, s := range spans[1:] {
		last := &merged[len(merged)-1]
		if s.span.Start <= last.span.End {
			if s.span.End > last.span.End {
				last.span.End = s.span.End
			}
			continue
		}
		merged = append(merged, s)
	}

	var b strings.Builder
	prev := 0
	for _, s := range merged {
		b.WriteString(body[prev:s.span.Start])
		b.WriteString("[secret:" + s.typ + "]")
		prev = s.span.End
	}
	b.WriteString(body[prev:])
	return b.String()
}

func len2(s Span) int { return s.End - s.Start }

// isPlaceholder rejects the variable portion of a candidate when it is a
// documentation placeholder rather than live material.
func isPlaceholder(s string) bool {
	if s == "" {
		return true
	}
	identical := true
	for i := 1; i < len(s); i++ {
		if s[i] != s[0] {
			identical = false
			break
		}
	}
	if identical {
		return true
	}
	up := strings.ToUpper(s)
	if strings.Contains(up, "EXAMPLE") || strings.Contains(up, "XXXX") {
		return true
	}
	return strings.ContainsAny(s, "<>")
}
