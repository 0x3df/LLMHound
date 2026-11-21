package secrets

import (
	"hash/crc32"
	"regexp"
)

const (
	githubTokenName = "github_token"
	// base62Alphabet is the checksum alphabet for classic GitHub tokens:
	// most-significant digit first, left-padded with '0' to width 6.
	base62Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

// githubTokenRe matches the classic personal-access / app tokens. The
// variable-length 2026 `ghs_` installation tokens and `github_pat_` tokens
// have no documented checksum and are deliberately not matched.
var githubTokenRe = regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36}`)

type githubDetector struct{}

func newGitHubDetector() Detector { return githubDetector{} }

func (githubDetector) Name() string { return githubTokenName }

func (githubDetector) Find(body string) []Match {
	var matches []Match
	for _, loc := range githubTokenRe.FindAllStringIndex(body, -1) {
		if !noWordNeighbours(body, loc[0], loc[1]) {
			continue
		}
		token := body[loc[0]:loc[1]]
		entropy, checksum := token[4:34], token[34:]
		if isPlaceholder(entropy) {
			continue
		}
		if GitHubChecksum(entropy) != checksum {
			continue
		}
		if isKnownExample(tokenDigest(token)) {
			continue
		}
		matches = append(matches, Match{Type: githubTokenName, Spans: []Span{{Start: loc[0], End: loc[1]}}})
	}
	return matches
}

// GitHubChecksum encodes the IEEE CRC-32 of the 30 ASCII entropy characters as
// the six-character base62 checksum GitHub appends to classic tokens.
func GitHubChecksum(entropy string) string {
	sum := crc32.ChecksumIEEE([]byte(entropy))
	var digits []byte
	for sum > 0 {
		digits = append([]byte{base62Alphabet[sum%62]}, digits...)
		sum /= 62
	}
	for len(digits) < 6 {
		digits = append([]byte{'0'}, digits...)
	}
	return string(digits)
}

// noWordNeighbours reports whether the bytes just outside [start,end) cannot
// extend the candidate. Go regexp has no lookaround, so this is checked
// manually to reject tokens embedded in longer runs.
func noWordNeighbours(body string, start, end int) bool {
	if start > 0 && isWordByte(body[start-1]) {
		return false
	}
	if end < len(body) && isWordByte(body[end]) {
		return false
	}
	return true
}

func isWordByte(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z'
}
