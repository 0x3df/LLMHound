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

// LoadMappingFile reads target-to-Computer mapping entries from a JSON or
// line-delimited file. It enforces bounds, ignores comments, canonicalizes targets,
// and rejects conflicting entries for the same target.
func LoadMappingFile(path string) ([]Mapping, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("mapping file path cannot be empty")
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat mapping file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("mapping file must be a regular file")
	}
	if info.Size() > MaxMappingFileBytes {
		return nil, fmt.Errorf("mapping file exceeds limit of %d bytes", MaxMappingFileBytes)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open mapping file: %w", err)
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, MaxMappingFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read mapping file: %w", err)
	}
	if len(data) > MaxMappingFileBytes {
		return nil, fmt.Errorf("mapping file exceeds limit of %d bytes", MaxMappingFileBytes)
	}

	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, errors.New("mapping file is empty")
	}

	var mappings []Mapping
	if trimmed[0] == '{' || trimmed[0] == '[' {
		mappings, err = parseJSONMappings(trimmed)
	} else {
		mappings, err = parseLineMappings(trimmed)
	}
	if err != nil {
		return nil, err
	}
	return rejectConflicts(mappings)
}

func rejectConflicts(mappings []Mapping) ([]Mapping, error) {
	seen := make(map[string]string, len(mappings))
	out := make([]Mapping, 0, len(mappings))
	for _, m := range mappings {
		prev, ok := seen[m.Target]
		if !ok {
			seen[m.Target] = m.ComputerID
			out = append(out, m)
			continue
		}
		if prev != m.ComputerID {
			return nil, fmt.Errorf("conflicting mapping entries for target %q", m.Target)
		}
	}
	return out, nil
}

func parseJSONMappings(data []byte) ([]Mapping, error) {
	// Attempt array of objects first: [{"target": "...", "computer_id": "..."}]
	type jsonEntry struct {
		Target     string `json:"target"`
		ComputerID string `json:"computer_id"`
	}
	var entries []jsonEntry
	if err := json.Unmarshal(data, &entries); err == nil && len(entries) > 0 {
		var mappings []Mapping
		for _, e := range entries {
			m, err := validateMappingEntry(e.Target, e.ComputerID)
			if err != nil {
				return nil, err
			}
			mappings = append(mappings, m)
		}
		return mappings, nil
	}

	// Attempt dictionary: {"target": "computer_id"}
	var dict map[string]string
	if err := json.Unmarshal(data, &dict); err == nil && len(dict) > 0 {
		var mappings []Mapping
		for target, compID := range dict {
			m, err := validateMappingEntry(target, compID)
			if err != nil {
				return nil, err
			}
			mappings = append(mappings, m)
		}
		return mappings, nil
	}

	return nil, errors.New("malformed JSON mapping format: must be array of objects or key-value map")
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

		if len(parts) != 2 {
			return nil, fmt.Errorf("line %d: invalid mapping line (expected target and Computer ID)", lineNum)
		}

		m, err := validateMappingEntry(parts[0], parts[1])
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

func validateMappingEntry(rawTarget, computerID string) (Mapping, error) {
	target, err := graph.ParseTarget(rawTarget)
	if err != nil {
		return Mapping{}, fmt.Errorf("invalid mapping target %q: %w", rawTarget, err)
	}
	if _, err := graph.ExistingComputerByID(computerID); err != nil {
		return Mapping{}, fmt.Errorf("invalid Computer ID %q: %w", computerID, err)
	}
	return Mapping{Target: target.Value(), ComputerID: computerID}, nil
}

// NewFromConfig builds a correlation Resolver from config.Config. If mappings are not
// provided but cfg.Correlation.MappingFile is specified, it loads mappings from the file.
func NewFromConfig(cfg config.Config, mappings []Mapping, propertyMatchSupported bool) (*Resolver, error) {
	if len(mappings) == 0 && cfg.Correlation.MappingFile != "" {
		loaded, err := LoadMappingFile(cfg.Correlation.MappingFile)
		if err != nil {
			return nil, fmt.Errorf("load correlation mapping file: %w", err)
		}
		mappings = loaded
	}
	return New(Config{
		Mappings:               mappings,
		ADSuffixes:             cfg.Correlation.ADDomainSuffixes,
		PropertyMatchSupported: propertyMatchSupported,
		ComputerProperty:       "name",
	})
}
