package bloodhound

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// PinnedCEVersion is the BloodHound Community Edition version validated by
// M0/R1-R9 and supported by the adapter.
const PinnedCEVersion = "v9.7.1"

// GateCheck records one capability check performed by ValidateAdapter.
type GateCheck struct {
	Name    string `json:"name"`
	OK      bool   `json:"ok"`
	Detail  string `json:"detail"`
	Warning string `json:"warning,omitempty"`
}

// GateReport summarizes whether a BloodHound CE instance satisfies LLMHound's
// adapter compatibility contract.
type GateReport struct {
	ServerVersion string      `json:"server_version"`
	Edition       string      `json:"edition"`
	Supported     bool        `json:"supported"`
	Checks        []GateCheck `json:"checks"`
}

// ValidateAdapter checks that the target BloodHound CE instance exposes every
// required API capability and matches PinnedCEVersion (unless allowUnvalidated
// is explicitly enabled).
func (c *Client) ValidateAdapter(ctx context.Context, allowUnvalidated bool) (*GateReport, error) {
	report := &GateReport{Supported: true}

	// 1. Version check.
	ver, err := c.Version(ctx)
	if err != nil {
		report.Supported = false
		report.Checks = append(report.Checks, GateCheck{Name: "version", OK: false, Detail: err.Error()})
		return report, fmt.Errorf("adapter gate failed on /api/version: %w", err)
	}
	report.ServerVersion = ver.ServerVersion
	report.Edition = ver.ProductEdition
	if ver.ServerVersion != PinnedCEVersion {
		if !allowUnvalidated {
			report.Supported = false
			report.Checks = append(report.Checks, GateCheck{
				Name:   "version",
				OK:     false,
				Detail: fmt.Sprintf("server_version %q != pinned %q (re-run lab/scripts/run-m0-checks.sh and run-m3-gate.sh or pass --allow-unvalidated-ce)", ver.ServerVersion, PinnedCEVersion),
			})
			return report, fmt.Errorf("unsupported BloodHound CE version %q (pinned %s); pass --allow-unvalidated-ce only after running validation", ver.ServerVersion, PinnedCEVersion)
		}
		report.Checks = append(report.Checks, GateCheck{
			Name:    "version",
			OK:      true,
			Detail:  fmt.Sprintf("server_version=%s", ver.ServerVersion),
			Warning: fmt.Sprintf("unvalidated CE version %q (pinned %s)", ver.ServerVersion, PinnedCEVersion),
		})
	} else {
		report.Checks = append(report.Checks, GateCheck{Name: "version", OK: true, Detail: ver.ServerVersion})
	}

	// 2. Extensions API.
	exts, err := c.ListExtensions(ctx)
	if err != nil {
		report.Supported = false
		report.Checks = append(report.Checks, GateCheck{Name: "extensions", OK: false, Detail: err.Error()})
		return report, fmt.Errorf("adapter gate failed on /api/v2/extensions: %w", err)
	}
	report.Checks = append(report.Checks, GateCheck{Name: "extensions", OK: true, Detail: fmt.Sprintf("%d extension(s)", len(exts))})

	// 3. Hyphenated source-kinds API (M0 Q5).
	kinds, err := c.ListSourceKinds(ctx)
	if err != nil {
		report.Supported = false
		report.Checks = append(report.Checks, GateCheck{Name: "source_kinds", OK: false, Detail: err.Error()})
		return report, fmt.Errorf("adapter gate failed on /api/v2/graphs/source-kinds: %w", err)
	}
	report.Checks = append(report.Checks, GateCheck{Name: "source_kinds", OK: true, Detail: fmt.Sprintf("%d source kind(s)", len(kinds))})

	// 4. Extension edges API (R2).
	edges, err := c.ListExtensionEdges(ctx)
	if err != nil {
		report.Supported = false
		report.Checks = append(report.Checks, GateCheck{Name: "extensions_edges", OK: false, Detail: err.Error()})
		return report, fmt.Errorf("adapter gate failed on /api/v2/extensions-edges: %w", err)
	}
	report.Checks = append(report.Checks, GateCheck{Name: "extensions_edges", OK: true, Detail: fmt.Sprintf("%d edge kind(s)", len(edges))})

	// 5. Read-only Cypher probe (R7).
	if _, err := c.Cypher(ctx, "MATCH (n) RETURN n LIMIT 1", false); err != nil {
		report.Supported = false
		report.Checks = append(report.Checks, GateCheck{Name: "cypher", OK: false, Detail: err.Error()})
		return report, fmt.Errorf("adapter gate failed on /api/v2/graphs/cypher: %w", err)
	}
	report.Checks = append(report.Checks, GateCheck{Name: "cypher", OK: true, Detail: "read-only cypher probe succeeded"})

	return report, nil
}

// TraversablePathKinds returns sorted traversable relationship kind names from
// GET /api/v2/extensions-edges, optionally including LLMHound_CanExecuteOn.
func (c *Client) TraversablePathKinds(ctx context.Context, includeCanExecuteOn bool) ([]string, error) {
	edges, err := c.ListExtensionEdges(ctx)
	if err != nil {
		return nil, err
	}
	var out []string
	seen := make(map[string]bool)
	for _, e := range edges {
		if !e.IsTraversable || e.Name == "" || seen[e.Name] {
			continue
		}
		if strings.HasPrefix(e.Name, "LLMHound_") && (!includeCanExecuteOn || e.Name != "LLMHound_CanExecuteOn") {
			continue
		}
		if !isSafeCypherEdgeKind(e.Name) {
			continue
		}
		seen[e.Name] = true
		out = append(out, e.Name)
	}
	sort.Strings(out)
	return out, nil
}

func isSafeCypherEdgeKind(name string) bool {
	for i := 0; i < len(name); i++ {
		c := name[i]
		isLetter := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		isDigit := c >= '0' && c <= '9'
		if i == 0 && !isLetter {
			return false
		}
		if !isLetter && !isDigit && c != '_' {
			return false
		}
	}
	return len(name) > 0
}
