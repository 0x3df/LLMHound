package graph

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const IdentityVersion = "1"

// Identity is a source-owned immutable identity. Only constructors can populate
// it; native Computer IDs and umbrella labels cannot be made source-owned.
type Identity struct {
	id      string
	scope   string
	kind    Kind
	ownerID string
}

func (i Identity) ID() string      { return i.id }
func (i Identity) Scope() string   { return i.scope }
func (i Identity) Kind() Kind      { return i.kind }
func (i Identity) OwnerID() string { return i.ownerID }

func validStableText(s string) bool {
	if s == "" || strings.TrimSpace(s) != s || !utf8.ValidString(s) {
		return false
	}
	for _, c := range s {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}

func newIdentity(scope string, kind Kind, fields ...string) (Identity, error) {
	if !validStableText(scope) {
		return Identity{}, errors.New("deployment scope must be stable nonempty text without surrounding whitespace or controls")
	}
	tuple := append([]string{IdentityVersion, SourceKind, scope, string(kind)}, fields...)
	data, err := json.Marshal(tuple)
	if err != nil {
		return Identity{}, err
	}
	sum := sha256.Sum256(data)
	return Identity{id: strings.ToUpper(hex.EncodeToString(sum[:])), scope: scope, kind: kind}, nil
}

func NewServiceIdentity(scope string, kind Kind, endpoint Endpoint) (Identity, error) {
	if !kind.IsService() {
		return Identity{}, errors.New("identity requires a concrete service kind")
	}
	if endpoint.scheme == "" {
		return Identity{}, errors.New("identity requires a canonical endpoint")
	}
	return newIdentity(scope, kind, endpoint.scheme, endpoint.host, strconv.Itoa(int(endpoint.port)), endpoint.basePath, endpoint.instanceKey)
}

// NewResourceIdentity preserves the exact protocol key (including case). Owner
// identity, not names, versions or correlation, defines service membership.
func NewResourceIdentity(scope string, kind Kind, owner Identity, key string) (Identity, error) {
	if !kind.IsResource() || !owner.kind.IsService() || owner.id == "" || scope != owner.scope {
		return Identity{}, errors.New("resource requires a concrete kind and owning service in the same scope")
	}
	if key == "" || !utf8.ValidString(key) {
		return Identity{}, errors.New("resource requires an exact nonempty UTF-8 stable key")
	}
	for _, c := range key {
		if unicode.IsControl(c) {
			return Identity{}, errors.New("resource key contains controls")
		}
	}
	id, err := newIdentity(scope, kind, owner.id, key)
	id.ownerID = owner.id
	return id, err
}

func NewNetworkEndpointIdentity(scope string, target Target) (Identity, error) {
	if target.value == "" {
		return Identity{}, errors.New("network endpoint requires a canonical target")
	}
	return newIdentity(scope, NetworkEndpoint, string(target.typ), target.value)
}

// RestoreIdentity recreates a source-owned Identity from verified components (e.g. during journal replay).
func RestoreIdentity(id, scope string, kind Kind, ownerID string) (Identity, error) {
	if !validStableText(id) || len(id) != 64 {
		return Identity{}, errors.New("identity requires a 64-character hex ID")
	}
	for _, c := range id {
		if (c < '0' || c > '9') && (c < 'A' || c > 'F') {
			return Identity{}, errors.New("identity ID must be uppercase hex")
		}
	}
	if !validStableText(scope) {
		return Identity{}, errors.New("identity requires a valid scope")
	}
	if kind == Computer || kind == AIService {
		return Identity{}, errors.New("identity cannot be Computer or AIService")
	}
	if _, err := kind.Emitted(); err != nil {
		return Identity{}, err
	}
	if kind.IsResource() {
		if !validStableText(ownerID) || len(ownerID) != 64 {
			return Identity{}, errors.New("resource identity requires a valid owning service ID")
		}
		for _, c := range ownerID {
			if (c < '0' || c > '9') && (c < 'A' || c > 'F') {
				return Identity{}, errors.New("owning service ID must be uppercase hex")
			}
		}
	} else if ownerID != "" {
		return Identity{}, errors.New("non-resource identity cannot have an owner ID")
	}
	return Identity{id: id, scope: scope, kind: kind, ownerID: ownerID}, nil
}
