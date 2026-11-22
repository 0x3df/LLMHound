package secrets

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"regexp"
	"strings"
)

const privateKeyName = "private_key"

// pemBeginRe matches unencrypted private key PEM labels only. ENCRYPTED
// PRIVATE KEY and DSA PRIVATE KEY labels are never matched.
var pemBeginRe = regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----`)

// maxPEMInnerBytes bounds the distance from BEGIN to the first matching END.
const maxPEMInnerBytes = 16 << 10

type privateKeyDetector struct{}

func newPrivateKeyDetector() Detector { return privateKeyDetector{} }

func (privateKeyDetector) Name() string { return privateKeyName }

func (privateKeyDetector) Find(body string) []Match {
	var matches []Match
	for _, loc := range pemBeginRe.FindAllStringIndex(body, -1) {
		// "-----BEGIN " is 11 bytes and the trailing dashes are 5 bytes.
		label := body[loc[0]+11 : loc[1]-5]
		endMarker := "-----END " + label + "-----"
		windowEnd := loc[1] + maxPEMInnerBytes
		if windowEnd > len(body) {
			windowEnd = len(body)
		}
		rel := strings.Index(body[loc[1]:windowEnd], endMarker)
		if rel < 0 || loc[1]+rel+len(endMarker) > windowEnd {
			continue
		}
		end := loc[1] + rel + len(endMarker)
		pubDigest, ok := privateKeyBodyParses(label, body[loc[1]:loc[1]+rel])
		if !ok {
			continue
		}
		m := Match{Type: privateKeyName, Spans: []Span{{Start: loc[0], End: end}}}
		if pubDigest != "" {
			m.PrincipalKind = "PubKeySHA256"
			m.PrincipalID = pubDigest
		}
		matches = append(matches, m)
	}
	return matches
}

// privateKeyBodyParses compacts the PEM body (which may carry JSON string
// escapes and line wrapping from a serialized notebook or an indented RFC
// listing), requires clean base64, and parses the key by label. Legacy
// encryption headers fail the match before parsing.
func privateKeyBodyParses(label, inner string) (string, bool) {
	if strings.Contains(inner, "Proc-Type:") || strings.Contains(inner, "DEK-Info:") {
		return "", false
	}
	compact := strings.ReplaceAll(inner, `\n`, "")
	compact = strings.ReplaceAll(compact, `\r`, "")
	compact = strings.ReplaceAll(compact, `\t`, "")
	compact = strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\r', '\n', '"', ',':
			return -1
		}
		return r
	}, compact)
	for i := range compact {
		c := compact[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '+', c == '/', c == '=':
		default:
			return "", false
		}
	}
	der, err := base64.StdEncoding.DecodeString(compact)
	if err != nil {
		return "", false
	}

	switch label {
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(der)
		if err != nil || isKnownExampleSPKI(&k.PublicKey) {
			return "", false
		}
		return pubKeySHA256(&k.PublicKey), true
	case "EC PRIVATE KEY":
		k, err := x509.ParseECPrivateKey(der)
		if err != nil || isKnownExampleSPKI(&k.PublicKey) {
			return "", false
		}
		return pubKeySHA256(&k.PublicKey), true
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			return "", false
		}
		if pub := pkixPublicOf(k); pub != nil {
			if isKnownExampleSPKI(pub) {
				return "", false
			}
			return pubKeySHA256(pub), true
		}
		return "", true
	case "OPENSSH PRIVATE KEY":
		pub, ok := parseOpenSSHUnencrypted(der)
		if !ok {
			return "", false
		}
		if pub != nil {
			if isKnownExampleSPKI(pub) {
				return "", false
			}
			return pubKeySHA256(pub), true
		}
		return "", true
	}
	return "", false
}

func pubKeySHA256(pub any) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func pkixPublicOf(priv any) crypto.PublicKey {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public()
	}
	return nil
}

// parseOpenSSHUnencrypted reports whether der is a complete, internally
// consistent openssh-key-v1 container for exactly one unencrypted private key
// of a supported type. Every SSH string is bounds checked before slicing; the
// public and private halves must agree cryptographically.
func parseOpenSSHUnencrypted(der []byte) (crypto.PublicKey, bool) {
	const magic = "openssh-key-v1\x00"
	if len(der) < len(magic) || !bytes.Equal(der[:len(magic)], []byte(magic)) {
		return nil, false
	}
	d := der[len(magic):]

	var ok bool
	if d, ok = sshStringEquals(d, "none"); !ok {
		return nil, false
	}
	if d, ok = sshStringEquals(d, "none"); !ok {
		return nil, false
	}
	var options []byte
	if options, d, ok = sshTakeString(d); !ok || len(options) != 0 {
		return nil, false
	}

	var nkeys uint32
	if nkeys, d, ok = sshTakeUint32(d); !ok || nkeys != 1 {
		return nil, false
	}

	var publicBlob, privateBlock []byte
	if publicBlob, d, ok = sshTakeString(d); !ok || len(publicBlob) == 0 {
		return nil, false
	}
	if privateBlock, d, ok = sshTakeString(d); !ok || len(privateBlock) == 0 || len(d) != 0 {
		return nil, false
	}

	pub, ok := parseSSHPublicKey(publicBlob)
	if !ok || !parseSSHPrivateBlock(privateBlock, pub) {
		return nil, false
	}
	return pub.cryptoPublic(), true
}

type sshPublicKey struct {
	keyType string
	ed25519 []byte
	rsaE    int
	rsaN    *big.Int
	curve   string
	point   []byte
}

func (p sshPublicKey) cryptoPublic() crypto.PublicKey {
	switch p.keyType {
	case "ssh-ed25519":
		return ed25519.PublicKey(p.ed25519)
	case "ssh-rsa":
		return &rsa.PublicKey{N: p.rsaN, E: p.rsaE}
	case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
		curve, ok, supported := sshECDSACurve(p.keyType, p.curve)
		if !ok || !supported {
			return nil
		}
		pk, err := ecdsa.ParseUncompressedPublicKey(curve, p.point)
		if err != nil {
			return nil
		}
		return pk
	}
	return nil
}

func parseSSHPublicKey(blob []byte) (sshPublicKey, bool) {
	keyTypeBytes, d, ok := sshTakeString(blob)
	if !ok {
		return sshPublicKey{}, false
	}
	pub := sshPublicKey{keyType: string(keyTypeBytes)}

	switch pub.keyType {
	case "ssh-ed25519":
		if pub.ed25519, d, ok = sshTakeString(d); !ok || len(pub.ed25519) != ed25519.PublicKeySize {
			return sshPublicKey{}, false
		}
	case "ssh-rsa":
		var e, n *big.Int
		if e, d, ok = sshTakePositiveMPInt(d); !ok {
			return sshPublicKey{}, false
		}
		if n, d, ok = sshTakePositiveMPInt(d); !ok || n.BitLen() < 2 {
			return sshPublicKey{}, false
		}
		if !e.IsInt64() || e.Int64() <= 1 || int64(int(e.Int64())) != e.Int64() {
			return sshPublicKey{}, false
		}
		pub.rsaE, pub.rsaN = int(e.Int64()), n
	case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
		var curveBytes, point []byte
		if curveBytes, d, ok = sshTakeString(d); !ok {
			return sshPublicKey{}, false
		}
		if point, d, ok = sshTakeString(d); !ok {
			return sshPublicKey{}, false
		}
		pub.curve = string(curveBytes)
		pub.point = point
		curve, curveMatches, supported := sshECDSACurve(pub.keyType, pub.curve)
		if !supported || !curveMatches {
			return sshPublicKey{}, false
		}
		if _, err := ecdsa.ParseUncompressedPublicKey(curve, point); err != nil {
			return sshPublicKey{}, false
		}
	default:
		return sshPublicKey{}, false
	}
	return pub, len(d) == 0
}

func parseSSHPrivateBlock(pb []byte, pub sshPublicKey) bool {
	var check1, check2 uint32
	var ok bool
	if check1, pb, ok = sshTakeUint32(pb); !ok {
		return false
	}
	if check2, pb, ok = sshTakeUint32(pb); !ok || check1 != check2 {
		return false
	}

	var keyTypeBytes []byte
	if keyTypeBytes, pb, ok = sshTakeString(pb); !ok || string(keyTypeBytes) != pub.keyType {
		return false
	}

	switch pub.keyType {
	case "ssh-ed25519":
		var publicPart, privatePart []byte
		if publicPart, pb, ok = sshTakeString(pb); !ok || len(publicPart) != ed25519.PublicKeySize {
			return false
		}
		if privatePart, pb, ok = sshTakeString(pb); !ok || len(privatePart) != ed25519.PrivateKeySize {
			return false
		}
		expected := ed25519.NewKeyFromSeed(privatePart[:ed25519.SeedSize])
		if !bytes.Equal(publicPart, pub.ed25519) || !bytes.Equal(privatePart, expected) {
			return false
		}
	case "ssh-rsa":
		var n, e, d, iqmp, p, q *big.Int
		if n, pb, ok = sshTakePositiveMPInt(pb); !ok {
			return false
		}
		if e, pb, ok = sshTakePositiveMPInt(pb); !ok {
			return false
		}
		if d, pb, ok = sshTakePositiveMPInt(pb); !ok {
			return false
		}
		if iqmp, pb, ok = sshTakePositiveMPInt(pb); !ok {
			return false
		}
		if p, pb, ok = sshTakePositiveMPInt(pb); !ok {
			return false
		}
		if q, pb, ok = sshTakePositiveMPInt(pb); !ok {
			return false
		}
		if n.Cmp(pub.rsaN) != 0 || !e.IsInt64() || int64(int(e.Int64())) != e.Int64() || int(e.Int64()) != pub.rsaE {
			return false
		}
		key := &rsa.PrivateKey{
			PublicKey: rsa.PublicKey{N: n, E: pub.rsaE},
			D:         d,
			Primes:    []*big.Int{p, q},
		}
		if err := key.Validate(); err != nil {
			return false
		}
		inverse := new(big.Int).ModInverse(q, p)
		if inverse == nil || inverse.Cmp(iqmp) != 0 {
			return false
		}
	case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
		var curveBytes, point []byte
		var d *big.Int
		if curveBytes, pb, ok = sshTakeString(pb); !ok || string(curveBytes) != pub.curve {
			return false
		}
		if point, pb, ok = sshTakeString(pb); !ok || !bytes.Equal(point, pub.point) {
			return false
		}
		if d, pb, ok = sshTakePositiveMPInt(pb); !ok {
			return false
		}
		curve, matches, supported := sshECDSACurve(pub.keyType, pub.curve)
		if !supported || !matches || d.Sign() <= 0 || d.Cmp(curve.Params().N) >= 0 {
			return false
		}
		// The private scalar must derive exactly the embedded public point.
		scalar := d.FillBytes(make([]byte, (curve.Params().BitSize+7)/8))
		priv, err := ecdsa.ParseRawPrivateKey(curve, scalar)
		if err != nil {
			return false
		}
		derived, err := priv.PublicKey.Bytes()
		if err != nil || !bytes.Equal(derived, point) {
			return false
		}
	default:
		return false
	}

	// Common suffix: comment followed by 1..8 padding bytes, exactly 1,2,...n.
	var comment []byte
	if comment, pb, ok = sshTakeString(pb); !ok || len(pb) < 1 || len(pb) > 8 {
		return false
	}
	_ = comment
	for i := range pb {
		if pb[i] != byte(i+1) {
			return false
		}
	}
	return true
}

func sshECDSACurve(keyType, curveName string) (curve elliptic.Curve, matches, supported bool) {
	want := ""
	switch keyType {
	case "ecdsa-sha2-nistp256":
		want, curve = "nistp256", elliptic.P256()
	case "ecdsa-sha2-nistp384":
		want, curve = "nistp384", elliptic.P384()
	case "ecdsa-sha2-nistp521":
		want, curve = "nistp521", elliptic.P521()
	default:
		return nil, false, false
	}
	return curve, curveName == want, true
}

func sshTakePositiveMPInt(d []byte) (n *big.Int, rest []byte, ok bool) {
	b, rest, ok := sshTakeString(d)
	if !ok || len(b) == 0 {
		return nil, nil, false
	}
	// Supported private-key fields are positive. A set high bit without a
	// leading zero is a negative SSH mpint; an unnecessary leading zero is
	// non-canonical and therefore rejected.
	if b[0]&0x80 != 0 || len(b) > 1 && b[0] == 0 && b[1]&0x80 == 0 {
		return nil, nil, false
	}
	n = new(big.Int).SetBytes(b)
	if n.Sign() <= 0 {
		return nil, nil, false
	}
	return n, rest, true
}

func sshTakeString(d []byte) (value, rest []byte, ok bool) {
	var n uint32
	if n, d, ok = sshTakeUint32(d); !ok || uint64(n) > uint64(len(d)) {
		return nil, nil, false
	}
	return d[:int(n)], d[int(n):], true
}

func sshTakeUint32(d []byte) (value uint32, rest []byte, ok bool) {
	if len(d) < 4 {
		return 0, nil, false
	}
	return binary.BigEndian.Uint32(d[:4]), d[4:], true
}

func sshStringEquals(d []byte, want string) (rest []byte, ok bool) {
	value, rest, ok := sshTakeString(d)
	return rest, ok && bytes.Equal(value, []byte(want))
}
