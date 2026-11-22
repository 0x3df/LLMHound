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
