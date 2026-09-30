package graph_test

import (
	"testing"

	"github.com/0x3df/LLMHound/internal/graph"
)

func endpoint(t *testing.T, raw string) graph.Endpoint {
	t.Helper()
	e, err := graph.ParseEndpoint(raw, "")
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestEquivalentEndpointSpellings(t *testing.T) {
	for _, pair := range [][2]string{
		{"HTTP://EXAMPLE.COM.", "http://example.com:080/"},
		{"https://Example.COM", "https://example.com:443/"},
		{"http://[2001:0db8:0000:0000:0000:0000:0000:0001]:80", "http://[2001:db8::1]/"},
		{"http://example.com/%7euser/%61pi", "http://example.com/~user/api"},
		{"http://example.com/a%2fb", "http://example.com/a%2Fb"},
	} {
		t.Run(pair[0], func(t *testing.T) {
			a, b := endpoint(t, pair[0]), endpoint(t, pair[1])
			if a != b {
				t.Fatalf("not equivalent: %#v != %#v", a, b)
			}
			if again := endpoint(t, a.String()); a != again {
				t.Fatalf("not idempotent: %v", a)
			}
		})
	}
	e := endpoint(t, "https://EXAMPLE.com:8443/api/")
	if e.Scheme() != "https" || e.Host() != "example.com" || e.Port() != 8443 || e.BasePath() != "/api/" {
		t.Fatalf("bad canonical fields: %v", e)
	}
}

func TestEndpointDimensionsRemainDistinct(t *testing.T) {
	base := endpoint(t, "http://example.com/api")
	for _, raw := range []string{
		"https://example.com:80/api", "http://other.example.com/api", "http://192.0.2.1/api",
		"http://example.com:81/api", "http://example.com/API", "http://example.com/api/",
		"http://example.com//api", "http://example.com/./api", "http://example.com/a%2Fpi",
	} {
		if got := endpoint(t, raw); got == base {
			t.Fatalf("collapsed %q", raw)
		}
	}
	if endpoint(t, "http://example.com/a%2Fb") == endpoint(t, "http://example.com/a/b") {
		t.Fatal("collapsed escaped separator")
	}
}

func TestMalformedEndpointsFailWithoutEchoingSecrets(t *testing.T) {
	for _, raw := range []string{
		"", "example.com", "//example.com", "ftp://example.com", "http:///api", "http://:80",
		"http://example.com:", "http://example.com:0", "http://example.com:65536", "http://example.com:-1",
		"http://user:secret@example.com", "http://example.com/#secret", "http://example.com?token=secret",
		"http://example.com/%xx", "http://example.com/white space", "http://[fe80::1%25en0]",
		"http://bad..example", "http://-bad.example", "http://example.com..", "http://☃.example",
		"http://2001:db8::1", "http://999.999.999.999", "http://example.com/%00", "http://example.com/%0A",
		"http://[192.0.2.1]", "http://K.example",
	} {
		t.Run(raw, func(t *testing.T) {
			_, err := graph.ParseEndpoint(raw, "")
			if err == nil {
				t.Fatal("accepted invalid endpoint")
			}
			if err.Error() == raw {
				t.Fatal("error leaked original input")
			}
		})
	}
}

func TestQueryRequiresNonSecretInstanceKey(t *testing.T) {
	a, err := graph.ParseEndpoint("https://example.com/api?token=secret", "instance-a")
	if err != nil {
		t.Fatal(err)
	}
	b, err := graph.ParseEndpoint("https://example.com/api?token=changed", "instance-a")
	if err != nil {
		t.Fatal(err)
	}
	c, err := graph.ParseEndpoint("https://example.com/api?token=secret", "instance-b")
	if err != nil {
		t.Fatal(err)
	}
	if a != b || a == c || a.String() != "https://example.com:443/api" {
		t.Fatalf("query leaked or instance key lost: %v", a)
	}
}

func TestCanonicalTargets(t *testing.T) {
	for _, pair := range [][2]string{{"Example.COM.", "example.com"}, {"2001:0db8::1", "2001:db8::1"}, {"[2001:db8::1]", "2001:db8::1"}} {
		a, err := graph.ParseTarget(pair[0])
		if err != nil {
			t.Fatal(err)
		}
		b, err := graph.ParseTarget(pair[1])
		if err != nil {
			t.Fatal(err)
		}
		if a != b {
			t.Fatalf("targets differ: %v %v", a, b)
		}
	}
	for _, raw := range []string{"", " a.example", "http://a.example", "a.example:80", "[a.example]", "a..example", "192.168.001.1", "fe80::1%en0", "K.example"} {
		if _, err := graph.ParseTarget(raw); err == nil {
			t.Fatalf("accepted target %q", raw)
		}
	}
	ip, _ := graph.ParseTarget("192.0.2.1")
	dns, _ := graph.ParseTarget("example.com")
	if ip.Type() != graph.IPTarget || ip.Value() != "192.0.2.1" || dns.Type() != graph.DNSTarget {
		t.Fatal("incorrect target types")
	}
}
