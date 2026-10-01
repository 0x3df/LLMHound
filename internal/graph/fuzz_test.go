package graph_test

import (
	"testing"

	"github.com/0x3df/LLMHound/internal/graph"
)

func FuzzEndpointCanonicalization(f *testing.F) {
	for _, raw := range []string{"http://EXAMPLE.com.", "https://[2001:db8::1]/api%2Fv1", "https://example.com?token=excluded", "http://K.example", "http://example.com/./a//", "http://example.com/%xx"} {
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		e, err := graph.ParseEndpoint(raw, "configured-instance")
		if err != nil {
			return
		}
		again, err := graph.ParseEndpoint(e.String(), e.InstanceKey())
		if err != nil || e != again {
			t.Fatalf("canonical roundtrip failed: %#v -> %#v (%v)", e, again, err)
		}
		a, err := graph.NewServiceIdentity("scope", graph.MCPServer, e)
		if err != nil {
			t.Fatal(err)
		}
		b, err := graph.NewServiceIdentity("scope", graph.MCPServer, again)
		if err != nil {
			t.Fatal(err)
		}
		if a != b {
			t.Fatal("canonical endpoint changed identity")
		}
	})
}

func FuzzTargetCanonicalization(f *testing.F) {
	for _, raw := range []string{"EXAMPLE.COM.", "192.0.2.1", "[2001:0db8::1]", "bad..example", "K.example", "fe80::1%en0"} {
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		target, err := graph.ParseTarget(raw)
		if err != nil {
			return
		}
		again, err := graph.ParseTarget(target.Value())
		if err != nil || target != again {
			t.Fatal("canonical target is not idempotent")
		}
	})
}
