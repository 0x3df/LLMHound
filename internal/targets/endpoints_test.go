package targets

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestPrepareEndpoints(t *testing.T) {
	dir := t.TempDir()
	epFile := filepath.Join(dir, "endpoints.txt")
	if err := os.WriteFile(epFile, []byte("# comment\n192.0.2.10:8888\nhttps://AI.Example.Test:8443/\n[2001:db8::1]:4000\n192.0.2.10:8888\n192.0.2.99:8000\n"), 0600); err != nil {
		t.Fatal(err)
	}

	got, err := PrepareEndpoints(
		[]string{"http://gateway.corp.example:4000"},
		[]string{epFile},
		[]string{"192.0.2.99"},
		nil,
		100,
	)
	if err != nil {
		t.Fatalf("PrepareEndpoints failed: %v", err)
	}

	want := []EndpointTarget{
		{Host: "192.0.2.10", Port: 8888, Scheme: ""},
		{Host: "2001:db8::1", Port: 4000, Scheme: ""},
		{Host: "ai.example.test", Port: 8443, Scheme: "https"},
		{Host: "gateway.corp.example", Port: 4000, Scheme: "http"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestPrepareEndpointsRejectsInvalid(t *testing.T) {
	for _, bad := range []string{
		"192.0.2.1",                    // missing port
		"192.0.2.1:0",                  // invalid port
		"192.0.2.1:99999",              // port out of range
		"ftp://ai.example.test:21",     // bad scheme
		"https://user:pass@a.test:443", // credentials
		"https://ai.example.test/api",  // path without port / path included
		"http://ai.example.test:80/v1", // path included
		"0.0.0.0:8888",                 // unspecified IP
	} {
		if _, err := PrepareEndpoints([]string{bad}, nil, nil, nil, 10); err == nil {
			t.Fatalf("accepted invalid endpoint %q", bad)
		}
	}
}
