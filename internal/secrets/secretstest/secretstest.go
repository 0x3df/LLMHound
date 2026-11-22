// Package secretstest builds secret-detection fixtures at test time. It is
// imported by tests only; production code must never use it. Positive keys
// and tokens are generated at runtime so that no live-looking secret literal
// is committed to the repository.
package secretstest

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"hash/crc32"
	"sync"
	"testing"
)

// checksumAlphabet and tokenChecksum intentionally mirror the detector's
// encoding of classic GitHub token checksums. They live here (not imported
// from the secrets package) because secretstest is imported by that package's
// tests; if the two implementations ever disagree, the corpus tests fail.
const checksumAlphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func tokenChecksum(entropy string) string {
	sum := crc32.ChecksumIEEE([]byte(entropy))
	var digits []byte
	for sum > 0 {
		digits = append([]byte{checksumAlphabet[sum%62]}, digits...)
		sum /= 62
	}
	for len(digits) < 6 {
		digits = append([]byte{'0'}, digits...)
	}
	return string(digits)
}

// GitHubToken assembles a classic GitHub token from a prefix and 30 ASCII
// entropy characters, computing the base62 CRC-32 checksum the detector
// expects. It panics on a malformed prefix or entropy so a broken fixture
// fails loudly instead of silently testing nothing.
func GitHubToken(prefix, entropy30 string) string {
	switch prefix {
	case "ghp", "gho", "ghu", "ghs", "ghr":
	default:
		panic(fmt.Sprintf("invalid GitHub token prefix %q", prefix))
	}
	if len(entropy30) != 30 {
		panic(fmt.Sprintf("entropy must be exactly 30 characters, got %d", len(entropy30)))
	}
	for i := range entropy30 {
		c := entropy30[i]
		if !(c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z') {
			panic(fmt.Sprintf("entropy must be alphanumeric, got %q", entropy30))
		}
	}
	return prefix + "_" + entropy30 + tokenChecksum(entropy30)
}

var (
	rsaOnce sync.Once
	rsaPEM  string
	rsaErr  error

	ecOnce sync.Once
	ecPEM  string
	ecErr  error

	edOnce sync.Once
	edPEM  string
	edErr  error

	sshOnce sync.Once
	sshPEM  string
	sshErr  error
)

// RSAPKCS1PEM returns a fresh 2048-bit RSA key in "RSA PRIVATE KEY" (PKCS#1)
// PEM form, generated once per package.
func RSAPKCS1PEM(t testing.TB) string {
	t.Helper()
	rsaOnce.Do(func() {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			rsaErr = err
			return
		}
		rsaPEM = string(pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		}))
	})
	if rsaErr != nil {
		t.Fatalf("generate RSA fixture: %v", rsaErr)
	}
	return rsaPEM
}

// ECPEM returns a fresh P-256 key in SEC1 "EC PRIVATE KEY" PEM form.
func ECPEM(t testing.TB) string {
	t.Helper()
	ecOnce.Do(func() {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			ecErr = err
			return
		}
		der, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			ecErr = err
			return
		}
		ecPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
	})
	if ecErr != nil {
		t.Fatalf("generate EC fixture: %v", ecErr)
	}
	return ecPEM
}

// Ed25519PKCS8PEM returns a fresh Ed25519 key in PKCS#8 "PRIVATE KEY" PEM form.
func Ed25519PKCS8PEM(t testing.TB) string {
	t.Helper()
	edOnce.Do(func() {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			edErr = err
			return
		}
		der, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			edErr = err
			return
		}
		edPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	})
	if edErr != nil {
		t.Fatalf("generate Ed25519 PKCS#8 fixture: %v", edErr)
	}
	return edPEM
}

// OpenSSHEd25519PEM returns a fresh Ed25519 key in the unencrypted
// openssh-key-v1 container ("OPENSSH PRIVATE KEY" PEM, cipher none, kdf none),
// hand-built to match the wire format the detector parses.
func OpenSSHEd25519PEM(t testing.TB) string {
	t.Helper()
	sshOnce.Do(func() {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			sshErr = err
			return
		}
		var check [4]byte
		if _, err := rand.Read(check[:]); err != nil {
			sshErr = err
			return
		}

		var pubBlob []byte
		pubBlob = appendSSHString(pubBlob, []byte("ssh-ed25519"))
		pubBlob = appendSSHString(pubBlob, pub)

		privBlock := binary.BigEndian.AppendUint32(nil, binary.BigEndian.Uint32(check[:]))
		privBlock = binary.BigEndian.AppendUint32(privBlock, binary.BigEndian.Uint32(check[:]))
		privBlock = appendSSHString(privBlock, []byte("ssh-ed25519"))
		privBlock = appendSSHString(privBlock, pub)
		privBlock = appendSSHString(privBlock, priv)                  // 64-byte seed+public
		privBlock = appendSSHString(privBlock, []byte("secretstest")) // comment
		pad := 8 - len(privBlock)%8
		for i := 1; i <= pad; i++ {
			privBlock = append(privBlock, byte(i))
		}

		out := []byte("openssh-key-v1\x00")
		out = appendSSHString(out, []byte("none"))
		out = appendSSHString(out, []byte("none"))
		out = appendSSHString(out, nil) // kdfoptions
		out = binary.BigEndian.AppendUint32(out, 1)
		out = appendSSHString(out, pubBlob)
		out = appendSSHString(out, privBlock)
		sshPEM = string(pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: out}))
	})
	if sshErr != nil {
		t.Fatalf("generate OpenSSH fixture: %v", sshErr)
	}
	return sshPEM
}

func appendSSHString(d, s []byte) []byte {
	d = binary.BigEndian.AppendUint32(d, uint32(len(s)))
	return append(d, s...)
}

// OpenSSHECDSAPEM returns a fresh P-256 key in the unencrypted openssh-key-v1
// container. When mismatch is true the private scalar does not derive the
// embedded public point, which the detector must reject.
func OpenSSHECDSAPEM(t testing.TB, mismatch bool) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA OpenSSH fixture: %v", err)
	}
	point, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatalf("encode ECDSA public key: %v", err)
	}
	scalar, err := key.Bytes()
	if err != nil {
		t.Fatalf("encode ECDSA private key: %v", err)
	}
	if mismatch {
		other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate mismatched scalar: %v", err)
		}
		if scalar, err = other.Bytes(); err != nil {
			t.Fatalf("encode mismatched scalar: %v", err)
		}
	}
	// SSH mpint: positive, so prefix 0x00 when the high bit is set.
	mpint := append([]byte(nil), scalar...)
	for len(mpint) > 1 && mpint[0] == 0 && mpint[1]&0x80 == 0 {
		mpint = mpint[1:]
	}
	if mpint[0]&0x80 != 0 {
		mpint = append([]byte{0}, mpint...)
	}

	const keyType, curve = "ecdsa-sha2-nistp256", "nistp256"
	var pubBlob []byte
	pubBlob = appendSSHString(pubBlob, []byte(keyType))
	pubBlob = appendSSHString(pubBlob, []byte(curve))
	pubBlob = appendSSHString(pubBlob, point)

	privBlock := binary.BigEndian.AppendUint32(nil, 0x5eed5eed)
	privBlock = binary.BigEndian.AppendUint32(privBlock, 0x5eed5eed)
	privBlock = appendSSHString(privBlock, []byte(keyType))
	privBlock = appendSSHString(privBlock, []byte(curve))
	privBlock = appendSSHString(privBlock, point)
	privBlock = appendSSHString(privBlock, mpint)
	privBlock = appendSSHString(privBlock, []byte("secretstest"))
	pad := 8 - len(privBlock)%8
	for i := 1; i <= pad; i++ {
		privBlock = append(privBlock, byte(i))
	}

	out := []byte("openssh-key-v1\x00")
	out = appendSSHString(out, []byte("none"))
	out = appendSSHString(out, []byte("none"))
	out = appendSSHString(out, nil)
	out = binary.BigEndian.AppendUint32(out, 1)
	out = appendSSHString(out, pubBlob)
	out = appendSSHString(out, privBlock)
	return string(pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: out}))
}
