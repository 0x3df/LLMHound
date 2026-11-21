// Package savedsearch generates the BloodHound saved queries shipped in
// extension/saved_searches. Queries are written once with logical kind names and
// rendered with emitted names (internal/graph/kinds.go) and the traversable path
// kinds snapshotted from the pinned CE (docs/05-ce-compatibility.md, R2).
package savedsearch

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/0x3df/LLMHound/internal/graph"
)

// Query is the Query Library import shape (M0 Q9).
type Query struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Query       string `json:"query"`
}

// StartPlaceholder marks the one value an analyst must replace in P2.
const StartPlaceholder = "<START_OBJECTID>"

// ParsePathKinds reads a snapshot of traversable CE edge kinds, one per line.
// Blank lines and # comments are ignored; names are validated so that a bad
// snapshot cannot inject Cypher.
func ParsePathKinds(data string) ([]string, error) {
	var kinds []string
	seen := make(map[string]bool)
	sc := bufio.NewScanner(strings.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for i, r := range line {
			isLetter := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
			isDigit := r >= '0' && r <= '9'
			if i == 0 && !isLetter {
				return nil, fmt.Errorf("invalid edge kind %q", line)
			}
			if !isLetter && !isDigit && r != '_' {
				return nil, fmt.Errorf("invalid edge kind %q", line)
			}
		}
		if strings.HasPrefix(line, graph.SourceKind+"_") {
			return nil, fmt.Errorf("path kinds must not include LLMHound kinds: %q", line)
		}
		if seen[line] {
			return nil, fmt.Errorf("duplicate edge kind %q", line)
		}
		seen[line] = true
		kinds = append(kinds, line)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan path kinds: %w", err)
	}
	if len(kinds) == 0 {
		return nil, fmt.Errorf("no path kinds")
	}
	return kinds, nil
}

func mustEmit(k graph.Kind) string {
	s, err := k.Emitted()
	if err != nil {
		panic(err)
	}
	return s
}

func mustEmitEdge(k graph.EdgeKind) string {
	s, err := k.Emitted()
	if err != nil {
		panic(err)
	}
	return s
}

// Generate renders every shipped query. Kind names come from internal/graph; the
// shapes follow the CE 9.7.1 rules recorded in docs/04-saved-queries.md.
func Generate(pathKinds []string) []Query {
	pk := strings.Join(pathKinds, "|")
	svc := mustEmit(graph.AIService)
	nep := mustEmit(graph.NetworkEndpoint)
	obs := mustEmitEdge(graph.ObservedAt)
	return []Query{
		{
			Name:        "LLMHound P1: AI hosts reachable from Domain Users",
			Description: "Shortest paths from Domain Users to hosts that run an AI service. Paths use only traversable AD/Azure edges; LLMHound adds no path.",
			Query: fmt.Sprintf("MATCH p = shortestPath((g:Group)-[:%s*1..]->(h))\n"+
				"WHERE g.objectid ENDS WITH '-513'\n  AND (h)<-[:%s]-(:%s)\nRETURN p\nLIMIT 100", pk, obs, svc),
		},
		{
			Name:        "LLMHound P2: shortest path from an asset to an AI host",
			Description: "Replace " + StartPlaceholder + " with the start node's objectid (upper-case), then run. Paths use only traversable AD/Azure edges.",
			Query: fmt.Sprintf("MATCH p = shortestPath((a {objectid: '%s'})-[:%s*1..]->(h))\n"+
				"WHERE (h)<-[:%s]-(:%s)\nRETURN p\nLIMIT 25", StartPlaceholder, pk, obs, svc),
		},
		{
			Name:        "LLMHound P4: anonymous AI services with an execution surface",
			Description: "Services that answered anonymous enumeration and expose a declared or inferred execution surface. exec_surface_basis says how; nothing was executed.",
			Query: fmt.Sprintf("MATCH (s:%s)-[:%s]->(h)\n"+
				"WHERE NOT h:%s\n"+
				"  AND s.auth_observed IN ['anonymous', 'mixed']\n"+
				"  AND any(x IN s.exec_surface WHERE x IN ['code_kernel','terminal','job_submit','code_eval','workflow_exec','tool_invocation'])\n"+
				"RETURN s, h\nLIMIT 100", svc, obs, nep),
		},
		{
			Name:        "LLMHound P6: unattributed AI services",
			Description: "Hand-off list for the normalization program: services whose target was not in the asset mapping.",
			Query:       fmt.Sprintf("MATCH (s:%s)-[:%s]->(n:%s)\nRETURN s, n\nLIMIT 1000", svc, obs, nep),
		},
	}
}

// FileName is the shipped file name for a query.
func FileName(q Query) string {
	name := strings.ToLower(q.Name)
	if i := strings.Index(name, ":"); i > 0 {
		name = name[:i]
	}
	name = strings.NewReplacer("llmhound ", "llmhound-", " ", "-").Replace(name)
	return name + ".json"
}

// Marshal renders a query as stable, indented JSON.
func Marshal(q Query) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false) // keep "->" readable in Cypher
	enc.SetIndent("", "  ")
	if err := enc.Encode(q); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
