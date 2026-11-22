package graph

import (
	"sort"
	"strings"
	"time"
	"unicode/utf8"
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

// ContentSummary summarizes default-on content-tier collection for one
// service. Bodies themselves never enter graph properties; they stay in the
// restricted .content.jsonl file.
type ContentSummary struct {
	Collected           bool
	Bytes               int64
	Truncated           bool
	SystemPromptPresent *bool
	ConfigCollected     *bool

	// SecretTypes lists detector types that matched in collected content.
	// Empty means "no high-precision match", never "clean".
	SecretTypes []string
	// SecretConfirmedAt is the scan observation time of the detection.
	SecretConfirmedAt time.Time

	// Exposed public principal identifiers associated with structure-verified
	// secret findings. Never contains secret material itself.
	ExposedAZAppIDs     []string
	ExposedAWSKeyIDs    []string
	ExposedPubKeySHA256 []string
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
	BuildID  string
	Commit   string

	Access     Access
	VantageKey string

	// AuthAdvertised is "none", "required", or "mixed" as declared by the
	// service (for example OAuth protected-resource metadata). Empty omits it.
	AuthAdvertised string

	// ExecSurface lists positively identified execution surfaces; the basis
	// says how that was established. Both are omitted when the list is empty.
	ExecSurface      []string
	ExecSurfaceBasis string

	// BackendRefs and StoreRefs list sanitized dependency references; the basis
	// says how they were established. Both are omitted when empty.
	BackendRefs      []string
	StoreRefs        []string
	BackendRefsBasis string

	// Inventory counts distinguish observed zero from unknown/unset (nil).
	ModelCount      *int
	ToolCount       *int
	ResourceCount   *int
	CollectionCount *int
	SkillCount      *int

	// TLS is nil when no TLS observation exists.
	TLS *TLSSummary

	// Content is nil when content-tier reads were disabled or did not run.
	Content *ContentSummary

	// EntraTenantID and EntraClientID record passively observed Microsoft Entra
	// OAuth/OIDC identifiers from anonymous endpoints or login redirects.
	EntraTenantID string
	EntraClientID string
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
	if b := boundReason(f.BuildID); b != "" {
		p["build_id"] = b
	}
	if c := boundReason(f.Commit); c != "" {
		p["commit"] = c
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
	backends := uniqueSorted(f.BackendRefs)
	if len(backends) > 0 {
		p["backend_refs"] = backends
	}
	stores := uniqueSorted(f.StoreRefs)
	if len(stores) > 0 {
		p["store_refs"] = stores
	}
	if (len(backends) > 0 || len(stores) > 0) && validBasis(f.BackendRefsBasis) {
		p["backend_refs_basis"] = f.BackendRefsBasis
	}
	for _, count := range []struct {
		key string
		val *int
	}{
		{"model_count", f.ModelCount},
		{"tool_count", f.ToolCount},
		{"resource_count", f.ResourceCount},
		{"collection_count", f.CollectionCount},
		{"skill_count", f.SkillCount},
	} {
		if count.val != nil && *count.val >= 0 {
			p[count.key] = *count.val
		}
	}
	if f.Content != nil && f.Content.Collected {
		p["content_bytes"] = f.Content.Bytes
		p["content_truncated"] = f.Content.Truncated
		if f.Content.SystemPromptPresent != nil {
			p["system_prompt_present"] = *f.Content.SystemPromptPresent
		}
		if f.Content.ConfigCollected != nil {
			p["config_collected"] = *f.Content.ConfigCollected
		}
		if types := uniqueSorted(f.Content.SecretTypes); len(types) > 0 && !f.Content.SecretConfirmedAt.IsZero() {
			p["has_exposed_secret"] = true
			p["secret_types"] = types
			p["secret_last_confirmed"] = f.Content.SecretConfirmedAt.UTC().Format(time.RFC3339)
		}
		if ids := uniqueSorted(f.Content.ExposedAZAppIDs); len(ids) > 0 {
			p["exposed_azapp_ids"] = ids
		}
		if ids := uniqueSorted(f.Content.ExposedAWSKeyIDs); len(ids) > 0 {
			p["exposed_aws_key_ids"] = ids
		}
		if digests := uniqueSorted(f.Content.ExposedPubKeySHA256); len(digests) > 0 {
			p["exposed_pubkey_sha256"] = digests
		}
	}
	if f.EntraTenantID != "" {
		p["entra_tenant_id"] = strings.ToLower(strings.TrimSpace(f.EntraTenantID))
	}
	if f.EntraClientID != "" {
		p["entra_client_id"] = strings.ToUpper(strings.TrimSpace(f.EntraClientID))
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
	case t.InsecureSet || t.Result == "unverified_override" || t.Result == "insecure_override":
		// Verification was bypassed by the operator. A recorded failure reason
		// keeps the fact that the certificate would not have verified; a clean
		// verification reason is not copied as a failure.
		p["tls_verification"] = "insecure_override"
		if t.Result == "failed" || t.Result == "unverified_override" {
			if r := boundReason(t.Reason); r != "" {
				p["tls_failure_reason"] = r
			}
		}
	case t.Result == "verified" || t.Result == "success":
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
// (untrusted) and strips control characters without splitting UTF-8 runes.
func boundReason(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > maxReasonLen {
		cut := maxReasonLen
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut]
	}
	return strings.TrimSpace(s)
}
