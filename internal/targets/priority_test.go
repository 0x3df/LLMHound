package targets_test

import (
	"reflect"
	"testing"

	"github.com/0x3df/LLMHound/internal/targets"
)

func TestPrioritizeTargets(t *testing.T) {
	mapping := map[string]string{
		"192.0.2.20": "S-1-5-21-20",
		"192.0.2.30": "S-1-5-21-TIER0",
	}
	lookup := func(tgt string) (string, bool) {
		id, ok := mapping[tgt]
		return id, ok
	}

	in := []string{"192.0.2.10", "192.0.2.20", "192.0.2.30"}
	prio := map[string]bool{"S-1-5-21-TIER0": true}

	got := targets.PrioritizeTargets(in, lookup, prio, false)
	want := []string{"192.0.2.30", "192.0.2.20", "192.0.2.10"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}

	mappedOnly := targets.PrioritizeTargets(in, lookup, prio, true)
	wantMapped := []string{"192.0.2.30", "192.0.2.20"}
	if !reflect.DeepEqual(mappedOnly, wantMapped) {
		t.Fatalf("mappedOnly got %v, want %v", mappedOnly, wantMapped)
	}
}

// BloodHound returns upper-cased objectids; a mapping file may hold lowercase
// Entra/Azure GUIDs. Prioritization must still match them.
func TestPrioritizeTargetsCaseInsensitiveObjectIDs(t *testing.T) {
	lookup := func(tgt string) (string, bool) {
		if tgt == "192.0.2.40" {
			return "6f1c2e3a-0b4d-4c5e-8f9a-1b2c3d4e5f60", true
		}
		return "", false
	}
	prio := map[string]bool{"6F1C2E3A-0B4D-4C5E-8F9A-1B2C3D4E5F60": true}
	got := targets.PrioritizeTargets([]string{"192.0.2.10", "192.0.2.40"}, lookup, prio, false)
	if want := []string{"192.0.2.40", "192.0.2.10"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
