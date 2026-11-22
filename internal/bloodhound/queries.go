package bloodhound

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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

// ListSavedQueries queries GET /api/v2/saved-queries.
func (c *Client) ListSavedQueries(ctx context.Context) ([]SavedQueryRecord, error) {
	status, body, err := c.doRaw(ctx, http.MethodGet, "/api/v2/saved-queries", "", nil, nil)
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
	return env.Data, nil
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

// ImportSavedQueries deletes any existing LLMHound* queries (CE rejects
// duplicate names with HTTP 400), packages queries into an in-memory ZIP, and
// uploads it to POST /api/v2/saved-queries/import.
func (c *Client) ImportSavedQueries(ctx context.Context, queries []savedsearch.Query) (int, error) {
	if len(queries) == 0 {
		return 0, nil
	}
	existing, err := c.ListSavedQueries(ctx)
	if err != nil {
		return 0, fmt.Errorf("list existing saved queries: %w", err)
	}
	for _, sq := range existing {
		if strings.HasPrefix(sq.Name, "LLMHound") {
			if err := c.DeleteSavedQuery(ctx, sq.ID); err != nil {
				return 0, fmt.Errorf("delete existing saved query %q (%d): %w", sq.Name, sq.ID, err)
			}
		}
	}

	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)
	for _, q := range queries {
		b, err := savedsearch.Marshal(q)
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

	status, body, err := c.doRaw(ctx, http.MethodPost, "/api/v2/saved-queries/import", "application/zip", zipBuf.Bytes(), nil)
	if err != nil {
		return 0, err
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return 0, fmt.Errorf("POST /api/v2/saved-queries/import returned HTTP %d: %s", status, truncateBody(body))
	}
	return len(queries), nil
}
