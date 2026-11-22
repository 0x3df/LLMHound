package secrets

import (
	"strings"
	"testing"

	"github.com/0x3df/LLMHound/internal/config"
	"github.com/0x3df/LLMHound/internal/secrets/secretstest"
)

func TestAzureDetectorPositives(t *testing.T) {
	clientUUID := "11112222-3333-4444-5555-666677778888"
	// Assembled from parts so no Entra-shaped literal sits verbatim in source.
	v2Secret := "abc" + "8Q~" + "Xy7Km2Pq9Rt4Vw1Nz6Jh3Df8Gs0Bc5LmQw"
	legacySecret := "AzR9mK2pQ7wX4vB8nL1cF6yT3dH5jZ0s~"

	cases := []struct {
		name   string
		body   string
		secret string
		wantID string
	}{
		{
			name:   "env_v2_secret_and_client_id",
			body:   "AZURE_CLIENT_ID=" + clientUUID + "\nAZURE_CLIENT_SECRET=" + v2Secret + "\n",
			secret: v2Secret,
			wantID: strings.ToUpper(clientUUID),
		},
		{
			name:   "json_config_with_tenant_and_client",
			body:   `{"azure_tenant_id":"aaaa0000-1111-2222-3333-444455556666","azure_client_id":"` + clientUUID + `","clientSecret":"` + v2Secret + `"}`,
			secret: v2Secret,
			wantID: strings.ToUpper(clientUUID),
		},
		{
			name:   "explicitly_labeled_entra_secret",
			body:   "entra_client_id: \"" + clientUUID + "\"\nentra_client_secret: \"" + legacySecret + "\"\n",
			secret: legacySecret,
			wantID: strings.ToUpper(clientUUID),
		},
	}

	red := NewRedactor(config.Secrets{})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, findings := red(tc.body)
			if len(findings) != 1 {
				t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
			}
			f := findings[0]
			if f.Type != azureClientSecretName {
				t.Errorf("Type = %q, want %q", f.Type, azureClientSecretName)
			}
			if f.PrincipalKind != "AZApp" || f.PrincipalID != tc.wantID {
				t.Errorf("principal = (%q, %q), want (AZApp, %q)", f.PrincipalKind, f.PrincipalID, tc.wantID)
			}
			if strings.Contains(out, tc.secret) {
				t.Errorf("secret leaked in redacted body")
			}
			if !strings.Contains(out, "[secret:azure_client_secret]") {
				t.Errorf("missing redaction marker in %q", out)
			}
			if !strings.Contains(out, clientUUID) {
				t.Errorf("public client_id UUID should remain readable in %q", out)
			}
		})
	}
}

func TestAzureDetectorNegatives(t *testing.T) {
	clientUUID := "11112222-3333-4444-5555-666677778888"
	tenantUUID := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	v2Secret := "abc" + "8Q~" + "Xy7Km2Pq9Rt4Vw1Nz6Jh3Df8Gs0Bc5LmQw"

	cases := []struct {
		name string
		body string
	}{
		{
			name: "tenant_id_only_no_client_id",
			body: "AZURE_TENANT_ID=" + tenantUUID + "\nAZURE_CLIENT_SECRET=" + v2Secret + "\n",
		},
		{
			name: "client_id_alone_no_secret",
			body: "AZURE_CLIENT_ID=" + clientUUID + "\n",
		},
		{
			name: "secret_alone_no_client_id",
			body: "AZURE_CLIENT_SECRET=" + v2Secret + "\n",
		},
		{
			name: "placeholder_secret",
			body: "AZURE_CLIENT_ID=" + clientUUID + "\nAZURE_CLIENT_SECRET=your_" + "8Q~" + "_example_placeholder_value_here_123\n",
		},
		{
			name: "all_zero_uuid",
			body: "AZURE_CLIENT_ID=00000000-0000-0000-0000-000000000000\nAZURE_CLIENT_SECRET=" + v2Secret + "\n",
		},
		{
			name: "generic_non_azure_client_secret_without_8Q_marker",
			body: "AUTH0_CLIENT_ID=" + clientUUID + "\nCLIENT_SECRET=aB3dE6gH9jK2mN5pQ8rS1tU4vW7xY0zA2b\n",
		},
		{
			name: "too_far_apart",
			body: "AZURE_CLIENT_ID=" + clientUUID + "\n" + strings.Repeat(" ", 600) + "AZURE_CLIENT_SECRET=" + v2Secret + "\n",
		},
	}

	red := NewRedactor(config.Secrets{})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, findings := red(tc.body)
			for _, f := range findings {
				if f.Type == azureClientSecretName {
					t.Fatalf("false positive %s on %q: %+v", tc.name, tc.body, findings)
				}
			}
			if out != tc.body {
				t.Errorf("negative body modified")
			}
		})
	}
}

func TestSecretPublicPrincipalMetadata(t *testing.T) {
	red := NewRedactor(config.Secrets{})

	awsBody := "aws_access_key_id = " + awsIDPrefix + awsIDSuffix + "\naws_secret_access_key = " + awsSecretSample + "\n"
	_, awsFindings := red(awsBody)
	if len(awsFindings) != 1 || awsFindings[0].PrincipalKind != "AWSKey" || awsFindings[0].PrincipalID != awsIDPrefix+awsIDSuffix {
		t.Fatalf("aws principal findings = %+v", awsFindings)
	}

	for _, tc := range []struct {
		name string
		pem  string
	}{
		{"rsa", secretstest.RSAPKCS1PEM(t)},
		{"openssh_ed25519", secretstest.OpenSSHEd25519PEM(t)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, pkFindings := red(tc.pem)
			if len(pkFindings) != 1 || pkFindings[0].PrincipalKind != "PubKeySHA256" || len(pkFindings[0].PrincipalID) != 64 {
				t.Fatalf("private_key principal findings = %+v", pkFindings)
			}
		})
	}
}
