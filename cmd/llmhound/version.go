package main

import "runtime/debug"

// version is stamped by release builds:
//
//	go build -ldflags "-X main.version=v1.0.0" ./cmd/llmhound
//
// Unstamped builds fall back to build info so evidence, journals, and the
// User-Agent never carry an unattributable "dev": a module install reports its
// module version, and a source build reports dev+<commit>[.dirty].
var version = "dev"

func init() {
	version = resolveVersion(version, debug.ReadBuildInfo)
}

func resolveVersion(stamped string, readBuildInfo func() (*debug.BuildInfo, bool)) string {
	if stamped != "" && stamped != "dev" {
		return stamped
	}
	bi, ok := readBuildInfo()
	if !ok || bi == nil {
		return "dev"
	}
	if v := bi.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	var rev string
	var dirty bool
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if rev == "" {
		return "dev"
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	v := "dev+" + rev
	if dirty {
		v += ".dirty"
	}
	return v
}
