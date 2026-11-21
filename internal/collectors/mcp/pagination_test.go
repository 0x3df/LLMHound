package mcp

import (
	"testing"
	"time"

	"github.com/0x3df/LLMHound/internal/graph"
)

func TestPaginateTruncationBoundaries(t *testing.T) {
	pages := map[string][]int{"": {1, 2}, "a": {3, 4}}
	next := map[string]string{"": "a", "a": ""}
	fetch := func(cursor string) ([]int, string, error) { return pages[cursor], next[cursor], nil }

	got, truncated, _, err := paginate(10, 4, "items", fetch)
	if err != nil || truncated || len(got) != 4 {
		t.Fatalf("exact item cap with no further page: got %v truncated=%v err=%v", got, truncated, err)
	}
	got, truncated, _, _ = paginate(10, 3, "items", fetch)
	if !truncated || len(got) != 3 {
		t.Fatalf("over item cap: got %v truncated=%v", got, truncated)
	}
	got, truncated, _, _ = paginate(1, 10, "items", fetch)
	if !truncated || len(got) != 2 {
		t.Fatalf("page cap with more pages: got %v truncated=%v", got, truncated)
	}
	got, truncated, _, _ = paginate(2, 10, "items", fetch)
	if truncated || len(got) != 4 {
		t.Fatalf("page cap met on final page: got %v truncated=%v", got, truncated)
	}
}

func TestBuildCorrelationIPv6Host(t *testing.T) {
	ep, err := graph.ParseEndpoint("http://[::1]:8080/mcp", "")
	if err != nil {
		t.Fatal(err)
	}
	srvID, err := graph.NewServiceIdentity("scope", graph.MCPServer, ep)
	if err != nil {
		t.Fatal(err)
	}
	obs := graph.Observation{SchemaVersion: "1", ScanID: "s", CollectorVersion: "t", EvidenceID: "e", Source: ep.String(), Surface: "mcp", ObservedAt: time.Unix(0, 0).UTC(), DeploymentScope: "scope", VantageKey: "v", Coverage: graph.CoverageComplete}
	if _, _, _, err := buildCorrelationEdgeAndFallback("scope", ep.Host(), srvID, obs, nil); err != nil {
		t.Fatalf("IPv6 host: %v", err)
	}
}
