package graph

import (
	"sort"
	"strings"
)

// Basis labels how a property value was established. Every classification
// property carries one so consumers can weigh it (see the graph model).
const (
	BasisObserved = "observed" // seen directly in a response
	BasisDeclared = "declared" // advertised by the service itself
	BasisInferred = "inferred" // derived by a documented rule from identity
)

// Execution surfaces a service can expose. Only positively identified surfaces
// are ever listed; unknown is expressed by omitting the property.
const (
	ExecCodeKernel     = "code_kernel"
	ExecTerminal       = "terminal"
	ExecJobSubmit      = "job_submit"
	ExecCodeEval       = "code_eval"
	ExecWorkflowExec   = "workflow_exec"
	ExecToolInvocation = "tool_invocation"
	ExecModelMutation  = "model_mutation"
)

// maxReasonLen bounds free text copied into a property.
const maxReasonLen = 200

// TLSSummary is the collector-neutral TLS observation for one service.
type TLSSummary struct {
	// Result is the transport's verdict: "verified", "failed", or
	// "unverified_override". Empty means no handshake was observed.
	Result      string
	Reason      string
	LeafSHA256  string // hex, any case
	Issuer      string
	NotAfter    string // RFC 3339
	TLSVersion  string
	InsecureSet bool
}

// ServiceFacts is the shared input for the flat service property contract
// (docs/02-graph-model.md#property-contract). Collectors fill what they have
// evidence for; every unset field is omitted, never defaulted, so that unknown
// stays unknown.
type ServiceFacts struct {
	Endpoint Endpoint
	Name     string
	Product  string
	Vendor   string

	Access     Access
	VantageKey string

	// AuthAdvertised is "none", "required", or "mixed" as declared by the
	// service (for example OAuth protected-resource metadata). Empty omits it.
	AuthAdvertised string

	// ExecSurface lists positively identified execution surfaces; the basis
	// says how that was established. Both are omitted when the list is empty.
	ExecSurface      []string
	ExecSurfaceBasis string

	// TLS is nil when no TLS observation exists.
	TLS *TLSSummary
}

// Properties returns the flat, CE-compatible service properties. Collectors
// add their surface-specific properties on top of the returned map.
func (f ServiceFacts) Properties() map[string]any {
	p := map[string]any{}
	if f.Name != "" {
		p["name"] = f.Name
		p["display_name"] = f.Name
	}
	if f.Endpoint.Host() != "" {
		p["endpoint"] = f.Endpoint.String()
		p["endpoint_host"] = f.Endpoint.Host()
		p["endpoint_port"] = int(f.Endpoint.Port())
		if f.Endpoint.Scheme() != "" {
			p["endpoint_scheme"] = f.Endpoint.Scheme()
		}
		if bp := f.Endpoint.BasePath(); bp != "" && bp != "/" {
			p["endpoint_base_path"] = bp
		}
	}
	if f.Product != "" {
		p["product"] = f.Product
	}
	if f.Vendor != "" {
		p["vendor"] = f.Vendor
	}
	if f.VantageKey != "" {
		p["vantage_key"] = f.VantageKey
	}
	for k, v := range f.Access.Properties() {
		p[k] = v
	}
	switch f.AuthAdvertised {
	case "none", "required", "mixed":
		p["auth_advertised"] = f.AuthAdvertised
		p["auth_advertised_basis"] = BasisDeclared
	}
	if surfaces := uniqueSorted(f.ExecSurface); len(surfaces) > 0 && validBasis(f.ExecSurfaceBasis) {
		p["exec_surface"] = surfaces
		p["exec_surface_basis"] = f.ExecSurfaceBasis
	}
	for k, v := range f.tlsProperties() {
		p[k] = v
	}
	return p
}

func (f ServiceFacts) tlsProperties() map[string]any {
	p := map[string]any{}
	if f.Endpoint.Scheme() == "http" {
		p["tls_verification"] = "n_a"
		return p
	}
	t := f.TLS
	if t == nil {
		return p
	}
	switch {
	case t.InsecureSet || t.Result == "unverified_override":
		// Verification was bypassed by the operator. A recorded failure reason
		// keeps the fact that the certificate would not have verified.
		p["tls_verification"] = "insecure_override"
		if t.Result == "failed" {
			if r := boundReason(t.Reason); r != "" {
				p["tls_failure_reason"] = r
			}
		}
	case t.Result == "verified":
		p["tls_verification"] = "ok"
	case t.Result == "failed":
		p["tls_verification"] = "failed"
		if r := boundReason(t.Reason); r != "" {
			p["tls_failure_reason"] = r
		}
	}
	if t.LeafSHA256 != "" {
		p["tls_leaf_sha256"] = strings.ToLower(t.LeafSHA256)
	}
	if t.Issuer != "" {
		p["tls_issuer"] = boundReason(t.Issuer)
	}
	if t.NotAfter != "" {
		p["tls_not_after"] = t.NotAfter
	}
	if t.TLSVersion != "" {
		p["tls_negotiated_version"] = t.TLSVersion
	}
	return p
}

func validBasis(b string) bool {
	return b == BasisObserved || b == BasisDeclared || b == BasisInferred
}

func uniqueSorted(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// boundReason trims free text that originates in a certificate or TLS error
// (untrusted) and strips control characters.
func boundReason(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > maxReasonLen {
		s = s[:maxReasonLen]
	}
	return strings.TrimSpace(s)
}
