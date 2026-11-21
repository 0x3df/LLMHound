package secrets

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
)

// knownExampleDigests holds SHA-256 digests of well-known documentation and
// standards-body test secrets, keyed by lowercase hex. A structurally valid
// match with one of these digests is published example material, not an
// exposure, and is dropped. Only digests live here, never the values.
var knownExampleDigests = map[string]bool{
	// Example classic GitHub token from the token-format documentation
	// ("ghp_" + 30 entropy chars + base62 CRC-32 checksum).
	"19781337c07714b9ad10ac269a6b75e64a5e35f747b4d752812b58b5d98449cf": true,

	// RFC 9500 §2.1 testRSA1024 (digest of the PKIX SPKI DER of its public key).
	"9a9e5b0f404f4e2d4386e38b04ac91e535946dc2a7f8d84a31404b476e5c35e1": true,
	// RFC 9500 §2.1 testRSA2048.
	"8fb6bad671cfe698393c453357da61b56d757ab8c0f3fb9c87f2849e63131878": true,
	// RFC 9500 §2.1 testRSA4096.
	"96465ea5dc9bb2da7b351d808a7196e5761f2412a5040131c68d719aaba28fb9": true,
	// RFC 9500 §2.3 testECCP256.
	"b2b04340cfaee616ec9c2c62d261b208e54bb197498df52e8cadede23ac0ba5e": true,
	// RFC 9500 §2.3 testECCP384.
	"c4c10105a0be0ed4dd3354428dc38a9bfee64da141ce16e75c94eda272f9dd3a": true,
	// RFC 9500 §2.3 testECCP521.
	"acb1b8327fef995e2458fdf5e3c33b2dc0749feabd6a894cb9bda9d70ac06c24": true,
}

// tokenDigest is the denylist key for a matched token string.
func tokenDigest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func isKnownExample(digest string) bool { return knownExampleDigests[digest] }

// isKnownExampleSPKI reports whether pub's PKIX SPKI DER digest is a known
// example. Keys whose SPKI cannot be marshalled are not denylisted.
func isKnownExampleSPKI(pub any) bool {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return false
	}
	sum := sha256.Sum256(der)
	return knownExampleDigests[hex.EncodeToString(sum[:])]
}
