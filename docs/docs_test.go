// Package docs_test keeps the documentation tree honest. It runs under
// `go test ./...` (and therefore in CI) and fails when a link or anchor breaks,
// a document is orphaned or missing from the index, a conflict marker is left
// behind, retired material loses its banner, or a live doc reintroduces a
// removed concept.
package docs_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"unicode"
)

const root = ".." // repository root, relative to this package

var (
	linkRE     = regexp.MustCompile(`\]\(([^)\s]+)\)`)
	headingRE  = regexp.MustCompile(`(?m)^(#{1,6})[ \t]+(.+?)[ \t]*$`)
	fenceRE    = regexp.MustCompile("(?s)```.*?```")
	numberedRE = regexp.MustCompile(`^\d\d-.+\.md$`)
)

// markdownFiles returns every tracked-looking .md file as a repo-relative slash path.
func markdownFiles(t *testing.T) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", ".runtime":
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(d.Name(), ".md") {
			rel, _ := filepath.Rel(root, path)
			files = append(files, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func read(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// slug mirrors GitHub's heading anchors: lower-case, drop everything except
// letters, digits, spaces, hyphens and underscores, spaces become hyphens.
func slug(heading string) string {
	heading = strings.ReplaceAll(heading, "`", "")
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(heading)) {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_':
			b.WriteRune(r)
		case r == ' ':
			b.WriteRune('-')
		}
	}
	return b.String()
}

// anchors returns the set of valid anchors in a document, with GitHub's -N suffix for duplicates.
func anchors(content string) map[string]bool {
	content = fenceRE.ReplaceAllString(content, "")
	seen := map[string]int{}
	out := map[string]bool{}
	for _, m := range headingRE.FindAllStringSubmatch(content, -1) {
		s := slug(m[2])
		if n := seen[s]; n > 0 {
			out[s+"-"+itoa(n)] = true
		} else {
			out[s] = true
		}
		seen[s]++
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var d []byte
	for ; n > 0; n /= 10 {
		d = append([]byte{byte('0' + n%10)}, d...)
	}
	return string(d)
}

// localLinks extracts relative links (outside code fences) from a document.
func localLinks(content string) []string {
	content = fenceRE.ReplaceAllString(content, "")
	var out []string
	for _, m := range linkRE.FindAllStringSubmatch(content, -1) {
		l := m[1]
		if strings.Contains(l, "://") || strings.HasPrefix(l, "mailto:") {
			continue
		}
		out = append(out, l)
	}
	return out
}

func TestLinksAndAnchorsResolve(t *testing.T) {
	files := markdownFiles(t)
	anchorCache := map[string]map[string]bool{}
	for _, f := range files {
		content := read(t, f)
		for _, link := range localLinks(content) {
			path, frag, _ := strings.Cut(link, "#")
			target := f
			if path != "" {
				target = filepath.ToSlash(filepath.Join(filepath.Dir(f), path))
			}
			info, err := os.Stat(filepath.Join(root, filepath.FromSlash(target)))
			if err != nil {
				t.Errorf("%s: broken link %q (no %s)", f, link, target)
				continue
			}
			if frag == "" || info.IsDir() || !strings.HasSuffix(target, ".md") {
				continue
			}
			if anchorCache[target] == nil {
				anchorCache[target] = anchors(read(t, target))
			}
			if !anchorCache[target][frag] {
				t.Errorf("%s: link %q has no heading anchor #%s in %s", f, link, frag, target)
			}
		}
	}
}

func TestEveryDocIsIndexedAndReachable(t *testing.T) {
	index := read(t, "docs/README.md")
	linkedFrom := map[string]bool{}
	for _, f := range markdownFiles(t) {
		for _, link := range localLinks(read(t, f)) {
			path, _, _ := strings.Cut(link, "#")
			if path == "" {
				continue
			}
			target := filepath.ToSlash(filepath.Join(filepath.Dir(f), path))
			if target != f {
				linkedFrom[target] = true
			}
		}
	}
	for _, f := range markdownFiles(t) {
		if !strings.HasPrefix(f, "docs/") || f == "docs/README.md" {
			continue
		}
		if !linkedFrom[f] {
			t.Errorf("%s is orphaned: nothing links to it", f)
		}
		if numberedRE.MatchString(filepath.Base(f)) && filepath.Dir(f) == "docs" {
			if !strings.Contains(index, "("+filepath.Base(f)+")") {
				t.Errorf("numbered doc %s is missing from docs/README.md", f)
			}
		}
	}
}

func TestNoConflictMarkers(t *testing.T) {
	for _, f := range markdownFiles(t) {
		for i, line := range strings.Split(read(t, f), "\n") {
			if strings.HasPrefix(line, "<<<<<<<") || strings.HasPrefix(line, ">>>>>>>") {
				t.Errorf("%s:%d: leftover merge conflict marker", f, i+1)
			}
		}
	}
}

func TestLegacyDocsAreBannered(t *testing.T) {
	for _, f := range markdownFiles(t) {
		if !strings.HasPrefix(f, "legacy/docs/") {
			continue
		}
		if !strings.HasPrefix(read(t, f), "> **ARCHIVED.**") {
			t.Errorf("%s must start with an ARCHIVED banner", f)
		}
	}
}

// Live documents must not present retired concepts as current. These files
// legitimately discuss history or measured CE behavior and are exempt.
func TestLiveDocsDoNotReintroduceRemovedConcepts(t *testing.T) {
	removed := []string{"UnauthenticatedAccess", "PublicAccess", "CollectionVantage", "ad_domain_suffixes", "docs/reference/", "docs/plans/"}
	exempt := map[string]bool{
		"docs/05-ce-compatibility.md": true, // measured CE behavior and the M0 spike's own fixtures
		"docs/07-decisions.md":        true, // records what was removed and why
		"docs/02-graph-model.md":      true, // states that no vantage node exists
		"AGENTS.md":                   true, // states the same invariant for agents
	}
	for _, f := range markdownFiles(t) {
		if strings.HasPrefix(f, "legacy/") || strings.HasPrefix(f, "lab/") || exempt[f] {
			continue
		}
		content := read(t, f)
		for _, term := range removed {
			if strings.Contains(content, term) {
				t.Errorf("%s mentions removed concept %q; update it or move the history to legacy/", f, term)
			}
		}
	}
}
