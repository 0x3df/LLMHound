package rules

import (
	"fmt"
	"strconv"
	"strings"
)

// SemVer represents a numeric major.minor.patch version.
type SemVer struct {
	Major int
	Minor int
	Patch int
}

// ParseSemVer parses a dotted numeric version (with optional leading v/V).
// Unknown, empty, pre-release, or non-numeric strings return (_, false) so
// path-qualification rules fail closed.
func ParseSemVer(raw string) (SemVer, bool) {
	s := strings.TrimSpace(raw)
	s = strings.TrimPrefix(s, "v")
	s = strings.TrimPrefix(s, "V")
	s = strings.TrimSpace(s)
	if s == "" {
		return SemVer{}, false
	}
	if idx := strings.IndexByte(s, '+'); idx >= 0 {
		s = s[:idx]
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return SemVer{}, false
	}
	nums := make([]int, 3)
	for i, p := range parts {
		if p == "" {
			return SemVer{}, false
		}
		for _, ch := range p {
			if ch < '0' || ch > '9' {
				return SemVer{}, false
			}
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return SemVer{}, false
		}
		nums[i] = n
	}
	return SemVer{Major: nums[0], Minor: nums[1], Patch: nums[2]}, true
}

func (v SemVer) compare(other SemVer) int {
	if v.Major != other.Major {
		if v.Major < other.Major {
			return -1
		}
		return 1
	}
	if v.Minor != other.Minor {
		if v.Minor < other.Minor {
			return -1
		}
		return 1
	}
	if v.Patch != other.Patch {
		if v.Patch < other.Patch {
			return -1
		}
		return 1
	}
	return 0
}

type constraint struct {
	op  string
	ver SemVer
}

// ParseRange validates and parses a comma-separated semver constraint list
// supporting >=, <=, >, <, and =.
func ParseRange(expr string) ([]constraint, error) {
	rawClauses := strings.Split(expr, ",")
	if len(rawClauses) == 0 {
		return nil, fmt.Errorf("empty version range")
	}
	var out []constraint
	for _, clause := range rawClauses {
		c := strings.TrimSpace(clause)
		if c == "" {
			return nil, fmt.Errorf("empty clause in version range %q", expr)
		}
		var op, verStr string
		for _, candidate := range []string{">=", "<=", ">", "<", "="} {
			if strings.HasPrefix(c, candidate) {
				op = candidate
				verStr = strings.TrimSpace(strings.TrimPrefix(c, candidate))
				break
			}
		}
		if op == "" {
			return nil, fmt.Errorf("missing comparison operator in %q", c)
		}
		v, ok := ParseSemVer(verStr)
		if !ok {
			return nil, fmt.Errorf("invalid semver %q in range %q", verStr, expr)
		}
		out = append(out, constraint{op: op, ver: v})
	}
	return out, nil
}

// MatchVersion reports whether version satisfies rangeExpr. Unknown, empty, or
// unparseable versions fail closed and return (false, nil).
func MatchVersion(version, rangeExpr string) (bool, error) {
	constraints, err := ParseRange(rangeExpr)
	if err != nil {
		return false, err
	}
	v, ok := ParseSemVer(version)
	if !ok {
		return false, nil
	}
	for _, c := range constraints {
		cmp := v.compare(c.ver)
		switch c.op {
		case ">=":
			if cmp < 0 {
				return false, nil
			}
		case "<=":
			if cmp > 0 {
				return false, nil
			}
		case ">":
			if cmp <= 0 {
				return false, nil
			}
		case "<":
			if cmp >= 0 {
				return false, nil
			}
		case "=":
			if cmp != 0 {
				return false, nil
			}
		}
	}
	return true, nil
}
