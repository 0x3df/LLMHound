package graph_test

import (
	"testing"

	"github.com/0x3df/LLMHound/internal/graph"
)

func service(t *testing.T, scope string, kind graph.Kind, raw string) graph.Identity {
	t.Helper()
	id, err := graph.NewServiceIdentity(scope, kind, endpoint(t, raw))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestServiceIdentityGoldenAndSeparation(t *testing.T) {
	base := service(t, "deployment-a", graph.OllamaInstance, "http://example.com")
	if base.ID() != "7C7642987E9667B2033D2433AD4C3BDA6F2535F50C5B9D093CF6BFE5D248AEE9" {
		t.Fatalf("identity v1 changed: %s", base.ID())
	}
	if base.Scope() != "deployment-a" || base.Kind() != graph.OllamaInstance {
		t.Fatal("lost scope/kind")
	}
	if base != service(t, "deployment-a", graph.OllamaInstance, "HTTP://EXAMPLE.COM.:080/") {
		t.Fatal("equivalent endpoint changed identity")
	}
	for _, other := range []graph.Identity{
		service(t, "deployment-b", graph.OllamaInstance, "http://example.com"),
		service(t, "deployment-a", graph.MCPServer, "http://example.com"),
		service(t, "deployment-a", graph.OllamaInstance, "https://example.com:80"),
		service(t, "deployment-a", graph.OllamaInstance, "http://192.0.2.1"),
		service(t, "deployment-a", graph.OllamaInstance, "http://virtual.example.com"),
		service(t, "deployment-a", graph.OllamaInstance, "http://example.com:81"),
		service(t, "deployment-a", graph.OllamaInstance, "http://example.com/api"),
	} {
		if other.ID() == base.ID() {
			t.Fatal("collapsed identity dimension")
		}
	}
}

func TestResourceAndVantageIdentities(t *testing.T) {
	owner := service(t, "scope", graph.MCPServer, "https://example.com/mcp")
	otherOwner := service(t, "scope", graph.MCPServer, "https://example.com/other")
	a, err := graph.NewResourceIdentity("scope", graph.MCPResource, owner, "resource://Case/key")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := graph.NewResourceIdentity("scope", graph.MCPResource, owner, "resource://Case/key")
	c, _ := graph.NewResourceIdentity("scope", graph.MCPResource, owner, "resource://case/key")
	d, _ := graph.NewResourceIdentity("scope", graph.MCPResource, otherOwner, "resource://Case/key")
	e, _ := graph.NewResourceIdentity("scope", graph.MCPTool, owner, "resource://Case/key")
	if a != b || a.ID() == c.ID() || a.ID() == d.ID() || a.ID() == e.ID() || a.OwnerID() != owner.ID() {
		t.Fatal("resource key/ownership identity incorrect")
	}
	v, err := graph.NewVantageIdentity("scope", "scanner/network-a")
	if err != nil {
		t.Fatal(err)
	}
	v2, _ := graph.NewVantageIdentity("scope", "scanner/network-a")
	v3, _ := graph.NewVantageIdentity("scope", "scanner/network-b")
	v4, _ := graph.NewVantageIdentity("other-scope", "scanner/network-a")
	if v != v2 || v.ID() == v3.ID() || v.ID() == v4.ID() {
		t.Fatal("vantage is not scoped/stable")
	}
	// Unambiguous tuple encoding, not delimiter concatenation.
	x, _ := graph.NewVantageIdentity("a|b", "c")
	y, _ := graph.NewVantageIdentity("a", "b|c")
	if x.ID() == y.ID() {
		t.Fatal("ambiguous tuple")
	}
}

func TestNetworkEndpointIsScopedTargetNotMachine(t *testing.T) {
	dns, _ := graph.ParseTarget("Example.COM.")
	ip, _ := graph.ParseTarget("192.0.2.1")
	a, err := graph.NewNetworkEndpointIdentity("scope", dns)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := graph.NewNetworkEndpointIdentity("scope", ip)
	c, _ := graph.NewNetworkEndpointIdentity("other", dns)
	if a.ID() == b.ID() || a.ID() == c.ID() {
		t.Fatal("target or scope merged")
	}
}

func TestInvalidIdentityInputs(t *testing.T) {
	e := endpoint(t, "http://example.com")
	for _, kind := range []graph.Kind{graph.Computer, graph.AIService, graph.AIModel, "Unknown"} {
		if _, err := graph.NewServiceIdentity("scope", kind, e); err == nil {
			t.Fatalf("accepted service kind %s", kind)
		}
	}
	for _, scope := range []string{"", " ", " scope", "scope\n", "\x00"} {
		if _, err := graph.NewServiceIdentity(scope, graph.MCPServer, e); err == nil {
			t.Fatalf("accepted scope %q", scope)
		}
	}
	if _, err := graph.NewServiceIdentity("scope", graph.MCPServer, graph.Endpoint{}); err == nil {
		t.Fatal("accepted empty endpoint")
	}
	owner := service(t, "scope", graph.MCPServer, "http://example.com")
	for _, tc := range []struct {
		scope string
		kind  graph.Kind
		owner graph.Identity
		key   string
	}{
		{"scope", graph.Computer, owner, "key"}, {"other", graph.MCPTool, owner, "key"},
		{"scope", graph.MCPTool, graph.Identity{}, "key"}, {"scope", graph.MCPTool, owner, ""},
	} {
		if _, err := graph.NewResourceIdentity(tc.scope, tc.kind, tc.owner, tc.key); err == nil {
			t.Fatal("accepted invalid resource")
		}
	}
	if _, err := graph.NewVantageIdentity("scope", ""); err == nil {
		t.Fatal("accepted empty vantage")
	}
	if _, err := graph.NewNetworkEndpointIdentity("scope", graph.Target{}); err == nil {
		t.Fatal("accepted empty target")
	}
}

func TestKindMappingAndNonTraversability(t *testing.T) {
	for _, kind := range graph.NodeKinds() {
		got, err := kind.Emitted()
		if err != nil {
			t.Fatal(err)
		}
		want := "LLMHound_" + string(kind)
		if got != want {
			t.Fatalf("%s emitted %s", kind, got)
		}
	}
	if got, err := graph.Computer.Emitted(); err != nil || got != "Computer" {
		t.Fatal("native kind qualified")
	}
	if _, err := graph.Kind("unknown").Emitted(); err == nil {
		t.Fatal("unknown kind accepted")
	}
	for _, kind := range graph.EdgeKinds() {
		if kind.IsTraversable() {
			t.Fatalf("%s traversable", kind)
		}
		if got, err := kind.Emitted(); err != nil || got != "LLMHound_"+string(kind) {
			t.Fatal("incorrect edge mapping")
		}
	}
	if _, err := graph.EdgeKind("unknown").Emitted(); err == nil {
		t.Fatal("unknown edge accepted")
	}
}

func TestRestoreIdentity(t *testing.T) {
	validID := "7C7642987E9667B2033D2433AD4C3BDA6F2535F50C5B9D093CF6BFE5D248AEE9"
	validOwnerID := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	// Valid service identity
	id, err := graph.RestoreIdentity(validID, "scope-a", graph.OllamaInstance, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.ID() != validID || id.Scope() != "scope-a" || id.Kind() != graph.OllamaInstance || id.OwnerID() != "" {
		t.Fatalf("restored identity mismatch: %+v", id)
	}

	// Valid resource identity
	resID, err := graph.RestoreIdentity(validID, "scope-a", graph.AIModel, validOwnerID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resID.ID() != validID || resID.Scope() != "scope-a" || resID.Kind() != graph.AIModel || resID.OwnerID() != validOwnerID {
		t.Fatalf("restored resource identity mismatch: %+v", resID)
	}

	// Rejections
	for _, tc := range []struct {
		name    string
		id      string
		scope   string
		kind    graph.Kind
		ownerID string
	}{
		{"lowercase id", "7c7642987e9667b2033d2433ad4c3bda6f2535f50c5b9d093cf6bfe5d248aee9", "scope-a", graph.OllamaInstance, ""},
		{"short id", "7C7642987E", "scope-a", graph.OllamaInstance, ""},
		{"non-hex id", "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ", "scope-a", graph.OllamaInstance, ""},
		{"empty scope", validID, "", graph.OllamaInstance, ""},
		{"whitespace scope", validID, "  ", graph.OllamaInstance, ""},
		{"computer kind", validID, "scope-a", graph.Computer, ""},
		{"umbrella AIService kind", validID, "scope-a", graph.AIService, ""},
		{"unknown kind", validID, "scope-a", graph.Kind("Invalid"), ""},
		{"resource missing owner", validID, "scope-a", graph.AIModel, ""},
		{"resource invalid owner", validID, "scope-a", graph.AIModel, "short"},
		{"service with owner", validID, "scope-a", graph.OllamaInstance, validOwnerID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := graph.RestoreIdentity(tc.id, tc.scope, tc.kind, tc.ownerID); err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
		})
	}
}

