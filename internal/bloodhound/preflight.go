package bloodhound

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"unicode"

	"github.com/0x3df/LLMHound/internal/emitter"
)

// PreflightChunkSize caps each Cypher objectid batch below CE's ~1,000-node cap (R7).
const PreflightChunkSize = 500

// preflightConcurrency bounds concurrent Cypher pre-flight queries against CE.
const preflightConcurrency = 4

// SkippedEdge records an edge withheld from the linking payload because one of
// its native endpoints was missing or a kindless stub in BloodHound CE.
type SkippedEdge struct {
	Kind    string `json:"kind"`
	StartID string `json:"start_id"`
	EndID   string `json:"end_id"`
	Reason  string `json:"reason"`
}

// CheckExistingNodes queries CE read-only in chunks of 500 to verify which
// objectids exist as real typed nodes (len(kinds) > 0, rejecting kindless
// stubs per R7). Keys in the returned map are upper-cased objectids.
func (c *Client) CheckExistingNodes(ctx context.Context, objectIDs []string) (map[string]bool, error) {
	seen := make(map[string]bool, len(objectIDs))
	var unique []string
	for _, id := range objectIDs {
		up := strings.ToUpper(strings.TrimSpace(id))
		if up == "" || strings.ContainsFunc(up, unicode.IsControl) {
			continue
		}
		if !seen[up] {
			seen[up] = true
			unique = append(unique, up)
		}
	}
	sort.Strings(unique)

	existing := make(map[string]bool, len(unique))
	if len(unique) == 0 {
		return existing, nil
	}

	var chunks [][]string
	for i := 0; i < len(unique); i += PreflightChunkSize {
		end := i + PreflightChunkSize
		if end > len(unique) {
			end = len(unique)
		}
		chunks = append(chunks, unique[i:end])
	}

	if len(chunks) == 1 {
		if err := c.checkExistingChunk(ctx, chunks[0], existing, nil); err != nil {
			return nil, err
		}
		return existing, nil
	}

	chunkCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	ch := make(chan []string, len(chunks))
	for _, chunk := range chunks {
		ch <- chunk
	}
	close(ch)

	workers := preflightConcurrency
	if len(chunks) < workers {
		workers = len(chunks)
	}

	var mu sync.Mutex
	var firstErr error
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for chunk := range ch {
				if chunkCtx.Err() != nil {
					return
				}
				if err := c.checkExistingChunk(chunkCtx, chunk, existing, &mu); err != nil {
					mu.Lock()
					if firstErr == nil {
						firstErr = err
						cancel()
					}
					mu.Unlock()
					return
				}
			}
		}()
	}
	wg.Wait()

	if firstErr != nil {
		return nil, firstErr
	}
	return existing, nil
}

func (c *Client) checkExistingChunk(ctx context.Context, chunk []string, existing map[string]bool, mu *sync.Mutex) error {
	encodedList, err := json.Marshal(chunk)
	if err != nil {
		return fmt.Errorf("encode objectid chunk: %w", err)
	}
	query := fmt.Sprintf("MATCH (n) WHERE n.objectid IN %s RETURN n", string(encodedList))
	res, err := c.Cypher(ctx, query, false)
	if err != nil {
		return fmt.Errorf("existence pre-flight cypher chunk: %w", err)
	}
	var found []string
	for _, node := range res.Nodes {
		if len(node.Kinds) == 0 {
			// Reject empty kindless stubs (M0 Q5 / R7).
			continue
		}
		objID := strings.ToUpper(strings.TrimSpace(node.ObjectID))
		if objID == "" {
			if rawObj, ok := node.Properties["objectid"].(string); ok {
				objID = strings.ToUpper(strings.TrimSpace(rawObj))
			}
		}
		if objID != "" {
			found = append(found, objID)
		}
	}
	if len(found) == 0 {
		return nil
	}
	if mu != nil {
		mu.Lock()
		defer mu.Unlock()
	}
	for _, objID := range found {
		existing[objID] = true
	}
	return nil
}

// FilterLinkingPayload verifies every native endpoint referenced in
// linkingPayload exists in CE before upload, returning a sourceless filtered
// payload and a report of skipped edges (preventing M0 Q5 stub creation).
func (c *Client) FilterLinkingPayload(
	ctx context.Context,
	linkingPayload emitter.Payload,
	baseNodeIDs map[string]bool,
) (emitter.Payload, []SkippedEdge, error) {
	var toCheck []string

	needsCheck := func(id string) bool {
		up := strings.ToUpper(strings.TrimSpace(id))
		if up == "" {
			return false
		}
		if baseNodeIDs != nil && baseNodeIDs[up] {
			return false
		}
		return true
	}

	for _, e := range linkingPayload.Graph.Edges {
		if needsCheck(e.Start.Value) {
			toCheck = append(toCheck, e.Start.Value)
		}
		if needsCheck(e.End.Value) {
			toCheck = append(toCheck, e.End.Value)
		}
	}

	existing, err := c.CheckExistingNodes(ctx, toCheck)
	if err != nil {
		return emitter.Payload{}, nil, err
	}

	var kept []emitter.EdgePayload
	var skipped []SkippedEdge
	for _, e := range linkingPayload.Graph.Edges {
		var missing []string
		startUp := strings.ToUpper(strings.TrimSpace(e.Start.Value))
		endUp := strings.ToUpper(strings.TrimSpace(e.End.Value))

		if needsCheck(e.Start.Value) && !existing[startUp] {
			missing = append(missing, "start:"+e.Start.Value)
		}
		if needsCheck(e.End.Value) && !existing[endUp] {
			missing = append(missing, "end:"+e.End.Value)
		}

		if len(missing) > 0 {
			skipped = append(skipped, SkippedEdge{
				Kind:    e.Kind,
				StartID: e.Start.Value,
				EndID:   e.End.Value,
				Reason:  "missing_or_stub_in_bloodhound (" + strings.Join(missing, ", ") + ")",
			})
			continue
		}
		kept = append(kept, e)
	}
	if kept == nil {
		kept = []emitter.EdgePayload{}
	}

	return emitter.Payload{
		Metadata: nil, // Must stay sourceless (M0 Q5).
		Graph: emitter.GraphPayload{
			Nodes: []emitter.NodePayload{},
			Edges: kept,
		},
	}, skipped, nil
}
