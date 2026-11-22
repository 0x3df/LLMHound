package main

import (
	"runtime/debug"
	"testing"
)

func TestResolveVersion(t *testing.T) {
	info := func(main string, settings ...debug.BuildSetting) func() (*debug.BuildInfo, bool) {
		return func() (*debug.BuildInfo, bool) {
			return &debug.BuildInfo{Main: debug.Module{Version: main}, Settings: settings}, true
		}
	}
	rev := debug.BuildSetting{Key: "vcs.revision", Value: "b76cbd5a1b2c3d4e5f60718293a4b5c6d7e8f901"}
	dirty := debug.BuildSetting{Key: "vcs.modified", Value: "true"}
	none := func() (*debug.BuildInfo, bool) { return nil, false }

	cases := []struct {
		name    string
		stamped string
		read    func() (*debug.BuildInfo, bool)
		want    string
	}{
		{"ldflags stamp wins", "v1.2.3", info("v9.9.9", rev), "v1.2.3"},
		{"module install", "dev", info("v1.0.0"), "v1.0.0"},
		{"source build", "dev", info("(devel)", rev), "dev+b76cbd5a1b2c"},
		{"dirty source build", "dev", info("(devel)", rev, dirty), "dev+b76cbd5a1b2c.dirty"},
		{"no build info", "dev", none, "dev"},
		{"no vcs info", "dev", info("(devel)"), "dev"},
	}
	for _, c := range cases {
		if got := resolveVersion(c.stamped, c.read); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}
