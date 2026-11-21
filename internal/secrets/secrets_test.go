package secrets

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0x3df/LLMHound/internal/config"
	"github.com/0x3df/LLMHound/internal/secrets/secretstest"
)

// Fixed, obviously fake AWS material for corpus rows. Assembled from pieces
// so no AWS-shaped literal is committed.
const (
	awsIDPrefix     = "AKIA"
	awsIDSuffix     = "Q7LM2RZK4WXN5TBV" // 16 chars, base32 alphabet
	awsSecretSample = "jW9sTx4mQpL7vBn2cRf8yUh5dGe3kZa6wSt1MnXq"
	awsEntropy      = "Zq3Lm9Tx2Vb7Nc4Hd8Kf1Pw6Rj5Ys0"
)

func TestCorpusPositives(t *testing.T) {
	pemRSA := secretstest.RSAPKCS1PEM(t)
	pemEC := secretstest.ECPEM(t)
	pemEd := secretstest.Ed25519PKCS8PEM(t)
	pemSSH := secretstest.OpenSSHEd25519PEM(t)
	tok := secretstest.GitHubToken("ghp", awsEntropy)
	awsID := awsIDPrefix + awsIDSuffix

	indented := func(p, indent string) string {
		var b strings.Builder
		for line := range strings.SplitSeq(p, "\n") {
			if line != "" {
				b.WriteString(indent)
			}
			b.WriteString(line)
			b.WriteString("\n")
		}
		return b.String()
	}

	type row struct {
		name     string
		body     string
		typ      string
		absent   []string
		line     int
		markers  int // number of [secret:<typ>] markers in output
		jsonBody bool
	}
	rows := []row{
		{name: "rsa_raw", body: pemRSA, typ: "private_key", absent: []string{"-----BEGIN", firstBase64Line(pemRSA)}, line: 1, markers: 1},
		{name: "ec_raw", body: pemEC, typ: "private_key", absent: []string{"-----BEGIN", firstBase64Line(pemEC)}, line: 1, markers: 1},
		{name: "ed25519_pkcs8_raw", body: pemEd, typ: "private_key", absent: []string{"-----BEGIN", firstBase64Line(pemEd)}, line: 1, markers: 1},
		{name: "openssh_ed25519_raw", body: pemSSH, typ: "private_key", absent: []string{"-----BEGIN", firstBase64Line(pemSSH)}, line: 1, markers: 1},
		{
			name: "rsa_in_json_notebook", typ: "private_key", line: 1, markers: 1, jsonBody: true,
			absent: []string{"-----BEGIN", firstBase64Line(pemRSA)},
			body:   notebookJSON(pemRSA),
		},
		{
			name: "rsa_in_yaml_block_scalar", typ: "private_key", line: 3, markers: 1,
			absent: []string{"-----BEGIN", firstBase64Line(pemRSA)},
			body:   "defaults:\n  tls_key: |\n" + indented(pemRSA, "    "),
		},
		{name: "github_ghp", body: tok, typ: "github_token", absent: []string{tok}, line: 1, markers: 1},
		{name: "github_gho", body: secretstest.GitHubToken("gho", awsEntropy), typ: "github_token", absent: []string{secretstest.GitHubToken("gho", awsEntropy)}, line: 1, markers: 1},
		{name: "github_ghu", body: secretstest.GitHubToken("ghu", awsEntropy), typ: "github_token", absent: []string{secretstest.GitHubToken("ghu", awsEntropy)}, line: 1, markers: 1},
		{name: "github_ghs", body: secretstest.GitHubToken("ghs", awsEntropy), typ: "github_token", absent: []string{secretstest.GitHubToken("ghs", awsEntropy)}, line: 1, markers: 1},
		{name: "github_ghr", body: secretstest.GitHubToken("ghr", awsEntropy), typ: "github_token", absent: []string{secretstest.GitHubToken("ghr", awsEntropy)}, line: 1, markers: 1},
		{name: "github_in_env_assignment", body: "export GITHUB_TOKEN=" + tok + "\n", typ: "github_token", absent: []string{tok}, line: 1, markers: 1},
		{name: "github_in_json_value", body: `{"cfg": "` + tok + `"}`, typ: "github_token", absent: []string{tok}, line: 1, markers: 1},
		{name: "github_at_body_start", body: tok + "\nsecond line\n", typ: "github_token", absent: []string{tok}, line: 1, markers: 1},
		{name: "github_at_body_end", body: "first line\nsecond " + tok, typ: "github_token", absent: []string{tok}, line: 2, markers: 1},
		{name: "aws_in_ini", body: "[default]\naws_access_key_id = " + awsID + "\naws_secret_access_key = " + awsSecretSample + "\n", typ: "aws_access_key", absent: []string{awsID, awsSecretSample}, line: 2, markers: 2},
		{name: "aws_in_json", body: `{"aws_access_key_id":"` + awsID + `","aws_secret_access_key":"` + awsSecretSample + `"}`, typ: "aws_access_key", absent: []string{awsID, awsSecretSample}, line: 1, markers: 2},
		{name: "aws_in_env_adjacent_lines", body: "export AWS_ACCESS_KEY_ID=" + awsID + "\nexport AWS_SECRET_ACCESS_KEY=" + awsSecretSample + "\n", typ: "aws_access_key", absent: []string{awsID, awsSecretSample}, line: 1, markers: 2},
	}

	red := NewRedactor(config.Secrets{})
	if red == nil {
		t.Fatal("default config must enable every detector")
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			out, findings := red(r.body)
			if len(findings) != 1 {
				t.Fatalf("findings = %d (%+v), want 1", len(findings), findings)
			}
			if findings[0].Type != r.typ {
				t.Fatalf("finding type = %q, want %q", findings[0].Type, r.typ)
			}
			if findings[0].Line != r.line {
				t.Fatalf("finding line = %d, want %d", findings[0].Line, r.line)
			}
			if got := strings.Count(out, "[secret:"+r.typ+"]"); got != r.markers {
				t.Fatalf("markers = %d, want %d; out: %s", got, r.markers, out)
			}
			for _, a := range r.absent {
				if strings.Contains(out, a) {
					t.Fatalf("redacted output still contains %q", a)
				}
			}
			if r.jsonBody && !json.Valid([]byte(out)) {
				t.Fatalf("redacted notebook output is not valid JSON: %s", out)
			}
		})
	}
}

func firstBase64Line(p string) string {
	for line := range strings.SplitSeq(p, "\n") {
		if strings.HasPrefix(line, "-----") {
			continue
		}
		if line != "" {
			return line
		}
	}
	return p
}

func notebookJSON(keyPEM string) string {
	lines := strings.Split(strings.TrimRight(keyPEM, "\n"), "\n")
	src := make([]any, len(lines))
	for i, l := range lines {
		src[i] = l
	}
	doc := map[string]any{"cells": []any{map[string]any{"source": src}}}
	b, err := json.Marshal(doc)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func rfc9500Keys(t testing.TB) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "rfc9500-keys.b64"))
	if err != nil {
		t.Fatal(err)
	}
	pems, err := base64.StdEncoding.DecodeString(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(pems), "-----BEGIN "); got != 6 {
		t.Fatalf("fixture holds %d PEM blocks, want 6", got)
	}
	return string(pems)
}

func indentLines(s, indent string) string {
	var b strings.Builder
	for line := range strings.SplitSeq(s, "\n") {
		if line != "" {
			b.WriteString(indent)
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}

func TestCorpusNegatives(t *testing.T) {
	pemRSA := secretstest.RSAPKCS1PEM(t)
	pemSSH := secretstest.OpenSSHEd25519PEM(t)
	tok := secretstest.GitHubToken("ghp", awsEntropy)
	awsID := awsIDPrefix + awsIDSuffix

	// A token with a deliberately wrong checksum: flip the final character.
	last := tok[len(tok)-1]
	alt := byte('Z')
	if last == 'Z' {
		alt = 'Y'
	}
	badChecksum := tok[:len(tok)-1] + string(alt)

	// OpenSSH negative blobs, hand-built with controlled fields.
	goodSSH, _ := pem.Decode([]byte(pemSSH))
	if goodSSH == nil {
		t.Fatal("openssh fixture must decode")
	}
	sshAES := buildOpenSSHBlob("aes256-ctr", "bcrypt", []byte("salthere"), 0x11223344, 0x11223344, "ssh-ed25519")
	sshBadChecks := buildOpenSSHBlob("none", "none", nil, 0x01020304, 0x05060708, "ssh-ed25519")
	sshTruncated := string(pem.EncodeToMemory(&pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: goodSSH.Bytes[:len(goodSSH.Bytes)/2],
	}))
	sshShortKDF := truncatedOpenSSHKDFPEM()
	sshMissingPrivateFields := incompleteOpenSSHPrivatePEM("ssh-ed25519")
	badPaddingDER := append([]byte(nil), goodSSH.Bytes...)
	badPaddingDER[len(badPaddingDER)-1] = 0
	sshBadPadding := string(pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: badPaddingDER}))
	sshTrailingDER := append(append([]byte(nil), goodSSH.Bytes...), 0)
	sshTrailing := string(pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: sshTrailingDER}))

	// 4 KiB of deterministic base64 noise.
	src := rand.New(rand.NewPCG(42, 7))
	noiseRaw := make([]byte, 3072)
	for i := range noiseRaw {
		noiseRaw[i] = byte(src.Uint64())
	}
	blob := base64.StdEncoding.EncodeToString(noiseRaw)

	rows := []struct {
		name string
		body string
	}{
		// private_key
		{name: "placeholder_between_markers", body: "-----BEGIN PRIVATE KEY-----\n<your-key>\n-----END PRIVATE KEY-----\n"},
		{name: "base64_that_is_not_a_key", body: "-----BEGIN PRIVATE KEY-----\n" + base64.StdEncoding.EncodeToString([]byte("this is not a private key body")) + "\n-----END PRIVATE KEY-----\n"},
		{name: "begin_without_end", body: "-----BEGIN RSA PRIVATE KEY-----\n" + firstBase64Line(pemRSA) + "\n"},
		{name: "mismatched_end_label", body: "-----BEGIN RSA PRIVATE KEY-----\n" + firstBase64Line(pemRSA) + "\n-----END PRIVATE KEY-----\n"},
		{name: "encrypted_private_key_label", body: "-----BEGIN ENCRYPTED PRIVATE KEY-----\n" + base64.StdEncoding.EncodeToString([]byte("anything at all")) + "\n-----END ENCRYPTED PRIVATE KEY-----\n"},
		{name: "legacy_encrypted_headers", body: insertAfterBegin(pemRSA, "Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,00112233445566778899AABBCCDDEEFF\n")},
		{name: "public_key_pem", body: "-----BEGIN PUBLIC KEY-----\n" + base64.StdEncoding.EncodeToString([]byte("public material")) + "\n-----END PUBLIC KEY-----\n"},
		{name: "certificate_pem", body: "-----BEGIN CERTIFICATE-----\n" + base64.StdEncoding.EncodeToString([]byte("certificate material")) + "\n-----END CERTIFICATE-----\n"},
		{name: "rfc9500_keys_as_is", body: rfc9500Keys(t)},
		{name: "rfc9500_keys_indented", body: indentLines(rfc9500Keys(t), "   ")},
		{name: "openssh_encrypted_cipher", body: sshAES},
		{name: "openssh_mismatched_checks", body: sshBadChecks},
		{name: "openssh_truncated", body: sshTruncated},
		{name: "openssh_short_kdf_string", body: sshShortKDF},
		{name: "openssh_missing_private_fields", body: sshMissingPrivateFields},
		{name: "openssh_bad_padding", body: sshBadPadding},
		{name: "openssh_trailing_bytes", body: sshTrailing},
		// github_token
		{name: "github_wrong_checksum", body: "token: " + badChecksum + "\n"},
		{name: "github_short_tail", body: "x " + "ghp_" + awsEntropy + "AbCdE" + "\n"},
		{name: "github_long_tail", body: "x " + "ghp_" + awsEntropy + "AbCdEfG" + "\n"},
		{name: "github_in_alnum_run", body: "abc" + tok + "xyz\n"},
		{name: "github_ghx_prefix", body: "ghx_" + awsEntropy + "zzZZ00" + "\n"},
		{name: "github_placeholder_entropy", body: secretstest.GitHubToken("ghp", strings.Repeat("a", 30)) + "\n"},
		{name: "github_example_entropy", body: secretstest.GitHubToken("ghp", "EXAMPLEb2c3d4f5g6h7j8k9l0m1n2p") + "\n"},
		{name: "github_known_example_token", body: "ghp_" + "IqIMNOZH6zOwIEB4" + "T9A2g4EHMy8Ji4" + "2q4HA5" + "\n"},
		{name: "github_fine_grained_pat", body: "github_pat_11AAAA0BBBB0CCCC0DDDD0EEEE0FFFF\n"},
		// aws_access_key
		{name: "aws_documented_example_pair", body: "id = " + awsIDPrefix + "IOSFODNN7EXAMPLE" + "\nsecret = " + "wJalrXUtnFEMI/K7MDENG/bPxRfiCY" + "EXAMPLEKEY" + "\n"},
		{name: "aws_lone_key_id", body: "id = " + awsID + "\n"},
		{name: "aws_lone_secret", body: "secret = " + awsSecretSample + "\n"},
		{name: "aws_hex_sha1_secret", body: "id = " + awsID + "\nsecret = a94a8fe5ccb19ba61c4c0873d391e987982fbbd3\n"},
		{name: "aws_placeholder_key_tail", body: "id = " + awsIDPrefix + strings.Repeat("A", 16) + "\nsecret = " + awsSecretSample + "\n"},
		{name: "aws_pair_too_far_apart", body: "id = " + awsID + "\n" + strings.Repeat("lorem ipsum dolor sit amet consectetur. ", 15) + awsSecretSample + "\n"},
		{name: "aws_key_id_outside_base32", body: "id = " + awsIDPrefix + "0O18" + "IOSFODNN7EXA" + "\nsecret = " + awsSecretSample + "\n"},
		{name: "aws_secret_inside_base64_blob", body: "id = " + awsID + "\n" + "AAAAAAAAAAAAAAAAAAAA" + awsSecretSample + "AAAAAAAAAAAAAAAAAAAA" + "\n"},
		// mixed noise
		{name: "base64_noise", body: blob + "\n"},
		{name: "uuids_and_digests", body: strings.Repeat("550e8400-e29b-41d4-a716-446655440000\n", 3) + "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\nchangeme\n"},
	}

	red := NewRedactor(config.Secrets{})
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			out, findings := red(r.body)
			if len(findings) != 0 {
				t.Fatalf("findings = %+v, want none", findings)
			}
			if out != r.body {
				t.Fatalf("body must be returned unchanged; got:\n%s\nwant:\n%s", out, r.body)
			}
		})
	}
}

// insertAfterBegin inserts lines after the BEGIN marker of a PEM block.
func insertAfterBegin(p, extra string) string {
	lines := strings.SplitN(strings.TrimRight(p, "\n"), "\n", 2)
	return lines[0] + "\n" + extra + lines[1] + "\n"
}

// buildOpenSSHBlob hand-builds an openssh-key-v1 container with the given
// container fields, for negative cases the fixtures cannot express.
func buildOpenSSHBlob(cipher, kdf string, kdfOptions []byte, check1, check2 uint32, keyType string) string {
	var pubBlob []byte
	pubBlob = appendSSHBytes(pubBlob, []byte(keyType))
	pubBlob = appendSSHBytes(pubBlob, make([]byte, 32))

	privBlock := make([]byte, 0, 64)
	privBlock = appendUint32(privBlock, check1)
	privBlock = appendUint32(privBlock, check2)
	privBlock = appendSSHBytes(privBlock, []byte(keyType))
	privBlock = appendSSHBytes(privBlock, make([]byte, 32))
	privBlock = appendSSHBytes(privBlock, make([]byte, 64))
	privBlock = appendSSHBytes(privBlock, []byte("test"))
	pad := 8 - len(privBlock)%8
	for i := 1; i <= pad; i++ {
		privBlock = append(privBlock, byte(i))
	}

	out := []byte("openssh-key-v1\x00")
	out = appendSSHBytes(out, []byte(cipher))
	out = appendSSHBytes(out, []byte(kdf))
	out = appendSSHBytes(out, kdfOptions)
	out = appendUint32(out, 1)
	out = appendSSHBytes(out, pubBlob)
	out = appendSSHBytes(out, privBlock)
	return string(pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: out}))
}
func truncatedOpenSSHKDFPEM() string {
	out := []byte("openssh-key-v1\x00")
	out = appendSSHBytes(out, []byte("none"))
	// Advertise a four-byte kdfname without providing its contents. The
	// detector must reject this without slicing the short string.
	out = appendUint32(out, 4)
	return string(pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: out}))
}

func incompleteOpenSSHPrivatePEM(keyType string) string {
	var publicBlob []byte
	publicBlob = appendSSHBytes(publicBlob, []byte(keyType))
	publicBlob = appendSSHBytes(publicBlob, make([]byte, ed25519.PublicKeySize))

	var privateBlock []byte
	privateBlock = appendUint32(privateBlock, 7)
	privateBlock = appendUint32(privateBlock, 7)
	privateBlock = appendSSHBytes(privateBlock, []byte(keyType))
	// Deliberately omit all key fields, comment, and padding.

	out := []byte("openssh-key-v1\x00")
	out = appendSSHBytes(out, []byte("none"))
	out = appendSSHBytes(out, []byte("none"))
	out = appendSSHBytes(out, nil)
	out = appendUint32(out, 1)
	out = appendSSHBytes(out, publicBlob)
	out = appendSSHBytes(out, privateBlock)
	return string(pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: out}))
}

func appendUint32(d []byte, v uint32) []byte {
	return append(d, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func appendSSHBytes(d, s []byte) []byte {
	d = appendUint32(d, uint32(len(s)))
	return append(d, s...)
}

func TestDetectorNamesMatchConfig(t *testing.T) {
	var names []string
	for _, d := range Detectors() {
		names = append(names, d.Name())
	}
	if strings.Join(names, ",") != strings.Join(config.SecretDetectorNames, ",") {
		t.Fatalf("detector names %v != config list %v", names, config.SecretDetectorNames)
	}
}

func TestGitHubChecksumEncoding(t *testing.T) {
	// The example token from the token-format write-up: CRC-32 0x9b121895
	// encodes as "2q4HA5". Split into pieces so the token literal is not
	// committed.
	entropy := "IqIMNOZH6zOwIEB4" + "T9A2g4EHMy8Ji4"
	if len(entropy) != 30 {
		t.Fatalf("entropy length = %d, want 30", len(entropy))
	}
	if got := GitHubChecksum(entropy); got != "2q4HA5" {
		t.Fatalf("GitHubChecksum = %q, want %q", got, "2q4HA5")
	}
}

func TestRedactorRespectsConfig(t *testing.T) {
	tok := secretstest.GitHubToken("ghp", awsEntropy)
	body := "token: " + tok + "\n"

	disabled := config.Secrets{Detectors: map[string]bool{"github_token": false}}
	red := NewRedactor(disabled)
	if red == nil {
		t.Fatal("partially disabled config must still return a redactor")
	}
	out, findings := red(body)
	if len(findings) != 0 {
		t.Fatalf("disabled detector must not report findings: %+v", findings)
	}
	if out != body {
		t.Fatalf("disabled detector must leave the token in the body: %s", out)
	}

	allDisabled := config.Secrets{Detectors: map[string]bool{
		"aws_access_key": false, "github_token": false, "private_key": false,
	}}
	if NewRedactor(allDisabled) != nil {
		t.Fatal("fully disabled config must return a nil redactor")
	}
}

type fakeDetector struct {
	typ     string
	matches []Match
}

func (f fakeDetector) Name() string { return f.typ }

func (f fakeDetector) Find(body string) []Match { return f.matches }

func TestRedactorOverlappingSpans(t *testing.T) {
	body := "0123456789abcdefghijKLMNOPQRST"
	out, findings := redact(body, []Detector{
		fakeDetector{typ: "github_token", matches: []Match{{Type: "github_token", Spans: []Span{{Start: 0, End: 10}}}}},
		fakeDetector{typ: "aws_access_key", matches: []Match{{Type: "aws_access_key", Spans: []Span{{Start: 5, End: 20}}}}},
	})
	if len(findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(findings))
	}
	if findings[0].Type != "github_token" || findings[1].Type != "aws_access_key" {
		t.Fatalf("finding types = %q, %q", findings[0].Type, findings[1].Type)
	}
	// The merged span carries the earliest-starting span's type and covers
	// the union [0,20).
	want := "[secret:github_token]" + body[20:]
	if out != want {
		t.Fatalf("out = %q, want %q", out, want)
	}
}

func FuzzRedactor(f *testing.F) {
	red := NewRedactor(config.Secrets{})
	f.Add("hello world")
	f.Add("ghp_" + awsEntropy + "zzZZ00")
	f.Add("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")
	f.Add(string([]byte{0x00, 0xff, 0xfe}))
	f.Fuzz(func(t *testing.T, body string) {
		out, findings := red(body)
		if len(findings) == 0 && strings.Contains(out, "[secret:") {
			t.Fatalf("markers without findings: %q", out)
		}
		for _, fd := range findings {
			if !strings.Contains(out, "[secret:") {
				t.Fatalf("finding %+v without marker: %q", fd, out)
			}
		}
		if len(out) > len(body)+32*len(findings) {
			t.Fatalf("redacted output grew: %d > %d + 32*%d", len(out), len(body), len(findings))
		}
	})
}
