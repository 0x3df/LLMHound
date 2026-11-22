package discovery_test

import (
	"testing"

	"github.com/0x3df/LLMHound/internal/discovery"
)

func TestDefinitionsForProfile(t *testing.T) {
	attack, err := discovery.DefinitionsForProfile(discovery.ProfileAttackPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(attack) != 10 {
		t.Fatalf("attack-path profile = %d definitions, want 10", len(attack))
	}
	for _, d := range attack {
		if d.Surface == discovery.SurfaceVLLM || d.Surface == discovery.SurfaceOpenAICompatible {
			t.Fatalf("attack-path should omit low-value surface %s", d.Surface)
		}
	}

	rce, err := discovery.DefinitionsForProfile(discovery.ProfileRCEOnly, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rce) != 5 {
		t.Fatalf("rce-only profile = %d definitions, want 5", len(rce))
	}

	full, err := discovery.DefinitionsForProfile(discovery.ProfileFull, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(full) != 15 {
		t.Fatalf("full profile = %d definitions, want 15", len(full))
	}

	custom, err := discovery.DefinitionsForProfile(discovery.ProfileFull, []string{"mcp", "jupyter"})
	if err != nil {
		t.Fatal(err)
	}
	if len(custom) != 2 || custom[0].Surface != discovery.SurfaceJupyter || custom[1].Surface != discovery.SurfaceMCP {
		t.Fatalf("custom surfaces = %+v", custom)
	}

	if _, err := discovery.DefinitionsForProfile("unknown", nil); err == nil {
		t.Fatal("expected unknown profile error")
	}
}

func TestUniquePorts(t *testing.T) {
	attack, _ := discovery.DefinitionsForProfile(discovery.ProfileAttackPath, nil)
	ports := discovery.UniquePorts(attack, []int{443, 8443, 8888})
	// 9 unique default ports in attack-path + 443 + 8443 = 11
	if len(ports) != 11 {
		t.Fatalf("UniquePorts = %v (len %d), want len 11", ports, len(ports))
	}
}
