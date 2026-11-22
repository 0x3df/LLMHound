package common

import (
	"net/http"
	"testing"

	"github.com/0x3df/LLMHound/internal/transport"
)

func TestExtractEntraOIDC(t *testing.T) {
	tenant := "11111111-2222-3333-4444-555555555555"
	client := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	wantClient := "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"

	t.Run("authorize_redirect_url", func(t *testing.T) {
		gotT, gotC := ExtractEntraOIDC("https://login.microsoftonline.com/" + tenant + "/oauth2/v2.0/authorize?client_id=" + client + "&response_type=code")
		if gotT != tenant || gotC != wantClient {
			t.Fatalf("got (%q, %q), want (%q, %q)", gotT, gotC, tenant, wantClient)
		}
	})

	t.Run("headers_location_and_www_authenticate", func(t *testing.T) {
		h := http.Header{}
		h.Set("Location", "https://login.microsoftonline.com/"+tenant+"/oauth2/v2.0/authorize?client_id="+client)
		gotT, gotC := ExtractEntraFromHeaders(h)
		if gotT != tenant || gotC != wantClient {
			t.Fatalf("headers got (%q, %q), want (%q, %q)", gotT, gotC, tenant, wantClient)
		}
	})

	t.Run("redirects", func(t *testing.T) {
		gotT, gotC := ExtractEntraFromRedirects([]transport.RedirectInfo{{
			FromURL: "https://jupyter.lab.local/hub/login",
			ToURL:   "https://login.microsoftonline.us/" + tenant + "/oauth2/authorize?client_id=" + client,
		}})
		if gotT != tenant || gotC != wantClient {
			t.Fatalf("redirects got (%q, %q), want (%q, %q)", gotT, gotC, tenant, wantClient)
		}
	})

	t.Run("explicit_json_keys", func(t *testing.T) {
		gotT, gotC := ExtractEntraOIDC(`{"oauth":{"microsoft_tenant_id":"` + tenant + `","microsoft_client_id":"` + client + `"}}`)
		if gotT != tenant || gotC != wantClient {
			t.Fatalf("json got (%q, %q), want (%q, %q)", gotT, gotC, tenant, wantClient)
		}
	})

	t.Run("ignores_non_entra_google_oauth_and_common_tenant", func(t *testing.T) {
		gotT, gotC := ExtractEntraOIDC(`{"issuer":"https://accounts.google.com","client_id":"` + client + `"}`)
		if gotT != "" || gotC != "" {
			t.Fatalf("expected empty for non-Entra provider, got (%q, %q)", gotT, gotC)
		}
		gotT2, gotC2 := ExtractEntraOIDC("https://login.microsoftonline.com/common/v2.0")
		if gotT2 != "" || gotC2 != "" {
			t.Fatalf("expected empty for common tenant without client_id, got (%q, %q)", gotT2, gotC2)
		}
	})
}
