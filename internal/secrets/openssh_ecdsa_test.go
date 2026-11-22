package secrets

import (
	"strings"
	"testing"

	"github.com/0x3df/LLMHound/internal/config"
	"github.com/0x3df/LLMHound/internal/secrets/secretstest"
)

// Covers the OpenSSH ECDSA path: the private scalar must derive the embedded
// public point (parse-verified), and a mismatched pair is not a key.
func TestOpenSSHECDSAPrivateKey(t *testing.T) {
	red := NewRedactor(config.Secrets{})

	good := secretstest.OpenSSHECDSAPEM(t, false)
	out, findings := red(good)
	if len(findings) != 1 || findings[0].Type != "private_key" {
		t.Fatalf("valid OpenSSH ECDSA key: findings = %+v", findings)
	}
	if strings.Contains(out, firstBase64Line(good)) {
		t.Fatal("key material must be redacted")
	}

	bad := secretstest.OpenSSHECDSAPEM(t, true)
	if _, findings := red(bad); len(findings) != 0 {
		t.Fatalf("scalar not matching the public point must not be reported: %+v", findings)
	}
}
