package bloodhound

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/0x3df/LLMHound/internal/savedsearch"
)

// SavedQueryRecord models an entry returned by GET /api/v2/saved-queries.
type SavedQueryRecord struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Query       string `json:"query"`
}

const (
	savedQueryPageSize = 100
	savedQueryMaxPages = 200
)

// ListSavedQueries lists every saved query visible to the caller, paging with
// skip/limit so a CE instance with many queries is read completely. Paging
// stops at a short page, or if the server ignores skip and repeats rows.
func (c *Client) ListSavedQueries(ctx context.Context) ([]SavedQueryRecord, error) {
	var out []SavedQueryRecord
	seen := make(map[int64]bool)
	for page := 0; page < savedQueryMaxPages; page++ {
		path := fmt.Sprintf("/api/v2/saved-queries?skip=%d&limit=%d", page*savedQueryPageSize, savedQueryPageSize)
		status, body, err := c.doRaw(ctx, http.MethodGet, path, "", nil, nil)
		if err != nil {
			return nil, err
		}
		if status != http.StatusOK {
			return nil, fmt.Errorf("GET /api/v2/saved-queries returned HTTP %d: %s", status, truncateBody(body))
		}
		var env struct {
			Data []SavedQueryRecord `json:"data"`
		}
		if err := json.Unmarshal(body, &env); err != nil {
			return nil, fmt.Errorf("decode /api/v2/saved-queries: %w", err)
		}
		added := 0
		for _, q := range env.Data {
			if !seen[q.ID] {
				seen[q.ID] = true
				out = append(out, q)
				added++
			}
		}
		if len(env.Data) < savedQueryPageSize || added == 0 {
			return out, nil
		}
	}
	return nil, fmt.Errorf("GET /api/v2/saved-queries: more than %d queries; refusing to guess which to replace", savedQueryPageSize*savedQueryMaxPages)
}

// CreateSavedQuery creates one saved query via POST /api/v2/saved-queries.
func (c *Client) CreateSavedQuery(ctx context.Context, q SavedQueryRecord) error {
	body, err := json.Marshal(map[string]string{"name": q.Name, "description": q.Description, "query": q.Query})
	if err != nil {
		return err
	}
	status, resp, err := c.doRaw(ctx, http.MethodPost, "/api/v2/saved-queries", "application/json", body, nil)
	if err != nil {
		return err
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return fmt.Errorf("POST /api/v2/saved-queries returned HTTP %d: %s", status, truncateBody(resp))
	}
	return nil
}

// DeleteSavedQuery deletes one saved query by ID via DELETE /api/v2/saved-queries/{id}.
func (c *Client) DeleteSavedQuery(ctx context.Context, id int64) error {
	status, body, err := c.doRaw(ctx, http.MethodDelete, fmt.Sprintf("/api/v2/saved-queries/%d", id), "", nil, nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK && status != http.StatusNoContent && status != http.StatusNotFound {
		return fmt.Errorf("DELETE /api/v2/saved-queries/%d returned HTTP %d: %s", id, status, truncateBody(body))
	}
	return nil
}

// shippedQueryName matches the naming scheme of queries LLMHound ships
// ("LLMHound P1: ...", "LLMHound I4: ..."), so a shipped query whose title
// changed between releases is still replaced rather than left stale.
var shippedQueryName = regexp.MustCompile(`^LLMHound [A-Z]{1,3}[0-9]{1,3}: `)

// ImportSavedQueries replaces LLMHound's shipped queries in CE. CE rejects
// duplicate names, so an existing query is deleted only when its name exactly
// matches one being imported or follows the shipped naming scheme;
// analyst-authored queries (even ones whose names start with "LLMHound") are
// never touched. If the import then fails, the deleted queries are recreated
// so a failed run does not lose them.
func (c *Client) ImportSavedQueries(ctx context.Context, queries []savedsearch.Query) (int, error) {
	if len(queries) == 0 {
		return 0, nil
	}

	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)
	importing := make(map[string]bool, len(queries))
	for _, q := range queries {
		importing[q.Name] = true
		b, err := json.MarshalIndent(q, "", "  ")
		if err != nil {
			return 0, fmt.Errorf("marshal saved query %q: %w", q.Name, err)
		}
		fw, err := zw.Create(savedsearch.FileName(q))
		if err != nil {
			return 0, fmt.Errorf("add %s to zip: %w", savedsearch.FileName(q), err)
		}
		if _, err := fw.Write(b); err != nil {
			return 0, fmt.Errorf("write %s to zip: %w", savedsearch.FileName(q), err)
		}
	}
	if err := zw.Close(); err != nil {
		return 0, fmt.Errorf("close saved queries zip: %w", err)
	}

	existing, err := c.ListSavedQueries(ctx)
	if err != nil {
		return 0, fmt.Errorf("list existing saved queries: %w", err)
	}
	var deleted []SavedQueryRecord
	restore := func(cause error) error {
		var failed []string
		for _, q := range deleted {
			if rerr := c.CreateSavedQuery(ctx, q); rerr != nil {
				failed = append(failed, q.Name)
			}
		}
		if len(failed) > 0 {
			return fmt.Errorf("%w; additionally failed to restore replaced queries %s", cause, strings.Join(failed, ", "))
		}
		return cause
	}
	for _, sq := range existing {
		if !importing[sq.Name] && !shippedQueryName.MatchString(sq.Name) {
			continue
		}
		if err := c.DeleteSavedQuery(ctx, sq.ID); err != nil {
			return 0, restore(fmt.Errorf("delete existing saved query %q (%d): %w", sq.Name, sq.ID, err))
		}
		deleted = append(deleted, sq)
	}

	status, body, err := c.doRaw(ctx, http.MethodPost, "/api/v2/saved-queries/import", "application/zip", zipBuf.Bytes(), nil)
	if err != nil {
		return 0, restore(err)
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return 0, restore(fmt.Errorf("POST /api/v2/saved-queries/import returned HTTP %d: %s", status, truncateBody(body)))
	}
	return len(queries), nil
}
