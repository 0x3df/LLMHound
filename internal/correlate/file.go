package correlate

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/0x3df/LLMHound/internal/config"
	"github.com/0x3df/LLMHound/internal/graph"
)

const MaxMappingFileBytes = 1 << 20 // 1 MiB

// LoadMappingFile reads asset-mapping entries (target to existing BloodHound
// objectid and kind) from a JSON or line-delimited file.
func LoadMappingFile(path string) ([]Mapping, error) {
	mappings, _, err := LoadMappingFileWithSource(path)
	return mappings, err
}

// LoadMappingFileWithSource reads asset-mapping entries plus an optional
// mapping_source revision identifier from an envelope JSON object:
//
//	{"source": "norm-2026-11-21", "mappings": [{"target": "...", "object_id": "...", "kind": "Computer"}]}
//
// Legacy JSON arrays, target-to-objectid maps, and line-delimited formats are
// also supported with an empty source.
func LoadMappingFileWithSource(path string) ([]Mapping, string, error) {
	if strings.TrimSpace(path) == "" {
		return nil, "", errors.New("mapping file path cannot be empty")
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, "", fmt.Errorf("stat mapping file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, "", errors.New("mapping file must be a regular file")
	}
	if info.Size() > MaxMappingFileBytes {
		return nil, "", fmt.Errorf("mapping file exceeds limit of %d bytes", MaxMappingFileBytes)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, "", fmt.Errorf("open mapping file: %w", err)
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, MaxMappingFileBytes+1))
	if err != nil {
		return nil, "", fmt.Errorf("read mapping file: %w", err)
	}
	if len(data) > MaxMappingFileBytes {
		return nil, "", fmt.Errorf("mapping file exceeds limit of %d bytes", MaxMappingFileBytes)
	}

	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, "", errors.New("mapping file is empty")
	}

	var mappings []Mapping
	var source string
	if trimmed[0] == '{' || trimmed[0] == '[' {
		mappings, source, err = parseJSONMappingsWithSource(trimmed)
	} else {
		mappings, err = parseLineMappings(trimmed)
	}
	if err != nil {
		return nil, "", err
	}
	clean, err := rejectConflicts(mappings)
	if err != nil {
		return nil, "", err
	}
	return clean, source, nil
}

func rejectConflicts(mappings []Mapping) ([]Mapping, error) {
	seen := make(map[string]Mapping, len(mappings))
	out := make([]Mapping, 0, len(mappings))
	for _, m := range mappings {
		prev, ok := seen[m.Target]
		if !ok {
			seen[m.Target] = m
			out = append(out, m)
			continue
		}
		if prev != m {
			return nil, fmt.Errorf("conflicting mapping entries for target %q", m.Target)
		}
	}
	return out, nil
}

func parseJSONMappingsWithSource(data []byte) ([]Mapping, string, error) {
	type jsonEntry struct {
		Target   string `json:"target"`
		ObjectID string `json:"object_id"`
		Kind     string `json:"kind"`
	}
	type jsonEnvelope struct {
		Source   string      `json:"source"`
		Mappings []jsonEntry `json:"mappings"`
	}
	if len(data) > 0 && data[0] == '{' {
		var env jsonEnvelope
		if err := json.Unmarshal(data, &env); err == nil && env.Mappings != nil {
			if len(env.Mappings) == 0 {
				return nil, "", errors.New("mapping envelope contains no mappings")
			}
			var mappings []Mapping
			for _, e := range env.Mappings {
				m, err := validateMappingEntry(e.Target, e.ObjectID, e.Kind)
				if err != nil {
					return nil, "", err
				}
				mappings = append(mappings, m)
			}
			return mappings, strings.TrimSpace(env.Source), nil
		}
	}

	var entries []jsonEntry
	if err := json.Unmarshal(data, &entries); err == nil && len(entries) > 0 {
		var mappings []Mapping
		for _, e := range entries {
			m, err := validateMappingEntry(e.Target, e.ObjectID, e.Kind)
			if err != nil {
				return nil, "", err
			}
			mappings = append(mappings, m)
		}
		return mappings, "", nil
	}

	var dict map[string]string
	if err := json.Unmarshal(data, &dict); err == nil && len(dict) > 0 {
		var mappings []Mapping
		for target, id := range dict {
			m, err := validateMappingEntry(target, id, "")
			if err != nil {
				return nil, "", err
			}
			mappings = append(mappings, m)
		}
		return mappings, "", nil
	}

	return nil, "", errors.New("malformed JSON mapping format: must be an array of {target, object_id, kind} objects, an envelope {source, mappings}, or a target-to-objectid map")
}

func parseLineMappings(data []byte) ([]Mapping, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	var mappings []Mapping
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if idx := strings.IndexByte(line, '#'); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if line == "" {
			continue
		}

		var parts []string
		if strings.Contains(line, ",") {
			for _, p := range strings.Split(line, ",") {
				if tr := strings.TrimSpace(p); tr != "" {
					parts = append(parts, tr)
				}
			}
		} else {
			parts = strings.Fields(line)
		}

		if len(parts) != 2 && len(parts) != 3 {
			return nil, fmt.Errorf("line %d: invalid mapping line (expected target, objectid[, kind])", lineNum)
		}
		kind := ""
		if len(parts) == 3 {
			kind = parts[2]
		}
		m, err := validateMappingEntry(parts[0], parts[1], kind)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNum, err)
		}
		mappings = append(mappings, m)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan mapping file: %w", err)
	}
	if len(mappings) == 0 {
		return nil, errors.New("no valid mappings found in file")
	}
	return mappings, nil
}

// DefaultNativeKind is assumed when an entry does not name a kind.
const DefaultNativeKind = graph.Computer

func validateMappingEntry(rawTarget, objectID, rawKind string) (Mapping, error) {
	target, err := graph.ParseTarget(rawTarget)
	if err != nil {
		return Mapping{}, fmt.Errorf("invalid mapping target %q: %w", rawTarget, err)
	}
	kind := DefaultNativeKind
	if strings.TrimSpace(rawKind) != "" {
		kind = graph.Kind(strings.TrimSpace(rawKind))
	}
	if _, err := graph.ExistingNodeByID(kind, objectID); err != nil {
		return Mapping{}, fmt.Errorf("invalid mapping for %q (objectid %q, kind %q): %w", rawTarget, objectID, kind, err)
	}
	return Mapping{Target: target.Value(), ObjectID: objectID, Kind: kind}, nil
}

// NewFromConfig builds a Resolver from the configured mapping file. With no
// mapping file every target falls back to a NetworkEndpoint, which is the
// intended hand-off to the normalizer.
func NewFromConfig(cfg config.Config) (*Resolver, error) {
	var mappings []Mapping
	var source string
	if cfg.Correlation.MappingFile != "" {
		loaded, src, err := LoadMappingFileWithSource(cfg.Correlation.MappingFile)
		if err != nil {
			return nil, fmt.Errorf("load correlation mapping file: %w", err)
		}
		mappings = loaded
		source = src
	}
	return NewWithSource(mappings, source)
}
