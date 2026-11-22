package discovery

import (
	"fmt"
	"strings"
)

// Discovery scan profile names matching config.Profile* constants.
const (
	ProfileAttackPath = "attack-path"
	ProfileRCEOnly    = "rce-only"
	ProfileFull       = "full"
)

var attackPathSurfaces = map[Surface]bool{
	SurfaceJupyter:   true,
	SurfaceRay:       true,
	SurfaceLangflow:  true,
	SurfaceFlowise:   true,
	SurfaceMCP:       true,
	SurfaceLiteLLM:   true,
	SurfaceMLflow:    true,
	SurfaceOpenWebUI: true,
	SurfaceQdrant:    true,
	SurfaceOllama:    true,
}

var rceOnlySurfaces = map[Surface]bool{
	SurfaceJupyter:  true,
	SurfaceRay:      true,
	SurfaceLangflow: true,
	SurfaceFlowise:  true,
	SurfaceMCP:      true,
}

// DefinitionsForProfile returns the ordered built-in definitions selected by
// profile (attack-path, rce-only, full) or an explicit surface list.
func DefinitionsForProfile(profile string, surfaces []string) ([]Definition, error) {
	all := BuiltinDefinitions()
	if len(surfaces) > 0 {
		wanted := make(map[Surface]bool, len(surfaces))
		for _, raw := range surfaces {
			s := Surface(strings.ToLower(strings.TrimSpace(raw)))
			if _, ok := DefinitionForSurface(s); !ok {
				return nil, fmt.Errorf("unknown discovery surface %q", raw)
			}
			wanted[s] = true
		}
		var out []Definition
		for _, def := range all {
			if wanted[def.Surface] {
				out = append(out, def)
			}
		}
		return out, nil
	}

	switch strings.ToLower(strings.TrimSpace(profile)) {
	case "", ProfileAttackPath:
		var out []Definition
		for _, def := range all {
			if attackPathSurfaces[def.Surface] {
				out = append(out, def)
			}
		}
		return out, nil
	case ProfileRCEOnly:
		var out []Definition
		for _, def := range all {
			if rceOnlySurfaces[def.Surface] {
				out = append(out, def)
			}
		}
		return out, nil
	case ProfileFull:
		return all, nil
	default:
		return nil, fmt.Errorf("unknown discovery profile %q", profile)
	}
}

// UniquePorts returns the sorted deduplicated list of default ports across defs
// plus any extraPorts.
func UniquePorts(defs []Definition, extraPorts []int) []int {
	seen := make(map[int]bool, len(defs)+len(extraPorts))
	for _, d := range defs {
		if d.DefaultPort > 0 && d.DefaultPort <= 65535 {
			seen[d.DefaultPort] = true
		}
	}
	for _, p := range extraPorts {
		if p > 0 && p <= 65535 {
			seen[p] = true
		}
	}
	out := make([]int, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	// Simple insertion/selection sort avoids extra import, list is tiny (<=30).
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
