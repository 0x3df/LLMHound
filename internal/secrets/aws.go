package secrets

import "regexp"

const awsKeyName = "aws_access_key"

// awsKeyIDRe matches AWS access key ids. The 16-character tail is base32
// (Crockford-restricted): A-Z and 2-7, never 0, 1, 8, or 9.
var awsKeyIDRe = regexp.MustCompile(`(AKIA|ASIA)[A-Z2-7]{16}`)

// awsSecretRe matches 40-character secret access keys inside larger text.
var awsSecretRe = regexp.MustCompile(`[A-Za-z0-9/+]{40}`)

type awsDetector struct{}

func newAWSDetector() Detector { return awsDetector{} }

func (awsDetector) Name() string { return awsKeyName }

// Find reports an aws_access_key match only for a key id and a checksum-
// shaped secret in the same item. A key id alone or a 40-character run alone
// is never a match.
func (awsDetector) Find(body string) []Match {
	ids := awsKeyIDRe.FindAllStringIndex(body, -1)
	if len(ids) == 0 {
		return nil
	}
	var cands []Span
	for _, loc := range awsSecretRe.FindAllStringIndex(body, -1) {
		if !awsSecretBoundary(body, loc[0], loc[1]) {
			continue
		}
		s := body[loc[0]:loc[1]]
		if !hasUpperLowerDigit(s) || isPlaceholder(s) {
			continue
		}
		cands = append(cands, Span{Start: loc[0], End: loc[1]})
	}
	if len(cands) == 0 {
		return nil
	}

	const maxPairDistance = 512
	used := make([]bool, len(cands))
	var matches []Match
	for _, id := range ids {
		if !awsIDBoundary(body, id[0], id[1]) {
			continue
		}
		if isPlaceholder(body[id[0]+4 : id[1]]) {
			continue
		}
		best, bestDist := -1, maxPairDistance+1
		for i, c := range cands {
			if used[i] {
				continue
			}
			d := id[0] - c.Start
			if d < 0 {
				d = -d
			}
			if d < bestDist {
				best, bestDist = i, d
			}
		}
		if best < 0 {
			continue
		}
		used[best] = true
		matches = append(matches, Match{
			Type:  awsKeyName,
			Spans: []Span{{Start: id[0], End: id[1]}, cands[best]},
		})
	}
	return matches
}

// awsIDBoundary rejects key ids adjacent to word characters.
func awsIDBoundary(body string, start, end int) bool {
	if start > 0 && isWordByte(body[start-1]) {
		return false
	}
	return end >= len(body) || !isWordByte(body[end])
}

// awsSecretBoundary rejects secret candidates adjacent to base64 alphabet
// characters, so a window cut out of a longer base64 blob never matches.
// Base64 padding '=' may only trail a base64 segment, so it is banned as a
// right neighbour but not as a left one: `export KEY=<secret>` is a real
// exposure shape.
func awsSecretBoundary(body string, start, end int) bool {
	if start > 0 && awsSecretExtender(body[start-1]) && body[start-1] != '=' {
		return false
	}
	return end >= len(body) || !awsSecretExtender(body[end])
}

func awsSecretExtender(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c == '/' || c == '+' || c == '='
}

func hasUpperLowerDigit(s string) bool {
	var upper, lower, digit bool
	for i := range s {
		switch {
		case s[i] >= 'A' && s[i] <= 'Z':
			upper = true
		case s[i] >= 'a' && s[i] <= 'z':
			lower = true
		case s[i] >= '0' && s[i] <= '9':
			digit = true
		}
	}
	return upper && lower && digit
}
