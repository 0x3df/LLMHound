package scanner_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/0x3df/LLMHound/internal/config"
	"github.com/0x3df/LLMHound/internal/scanner"
)

var docCheckRow = regexp.MustCompile("(?m)^\\| `([a-z0-9_]+)` \\|")

// `llmhound plan` is what operators review before authorizing a scan, so it
// must list exactly the checks each collector documents (docs/collectors are
// canonical). This catches plan drift such as an undocumented or unplanned
// request.
func TestPlanMatchesCollectorDocs(t *testing.T) {
	cfg := config.Defaults()
	cfg.Scope = "plan-scope"
	cfg.VantageKey = "plan-vantage"
	cfg.Targets = []string{"192.0.2.1"}
	cfg.Scan.Profile = config.ProfileFull
	cfg.Content.Mode = config.ContentModeFull
	s, err := scanner.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	plans := s.Plan([]string{"192.0.2.1"})
	if len(plans) != 1 {
		t.Fatalf("plans = %d", len(plans))
	}
	for _, sp := range plans[0].Surfaces {
		surface := string(sp.Surface)
		raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "collectors", surface+".md"))
		if err != nil {
			t.Errorf("%s: no collector doc: %v", surface, err)
			continue
		}
		var documented []string
		for _, m := range docCheckRow.FindAllStringSubmatch(string(raw), -1) {
			documented = append(documented, m[1])
		}
		var planned []string
		for _, c := range sp.Checks {
			planned = append(planned, c.CheckID)
		}
		sort.Strings(documented)
		sort.Strings(planned)
		if strings.Join(documented, ",") != strings.Join(planned, ",") {
			t.Errorf("%s: plan checks %v != documented checks %v", surface, planned, documented)
		}
	}
}
