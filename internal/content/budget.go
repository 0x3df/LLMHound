package content

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/0x3df/LLMHound/internal/config"
	"github.com/0x3df/LLMHound/internal/evidence"
)

// RecordInput supplies fields for one content-tier item before bounding and hashing.
type RecordInput struct {
	DeploymentScope string
	ScanID          string
	VantageKey      string
	ServiceID       string
	ResourceID      string
	Surface         string
	CheckID         string
	Source          string
	Kind            Kind
	Location        string
	MediaType       string
	ObservedAt      time.Time
	Body            string
	ResourceKey     string
}

// Budget tracks per-item, per-resource, and per-service content limits for one service.
type Budget struct {
	cfg           config.Content
	redactor      Redactor
	serviceBytes  int64
	resourceItems map[string]int
	truncated     bool
	reasons       []string
	reasonSeen    map[string]bool
	records       []Record
	findings      []Finding
}

// NewBudget creates a content Budget from cfg, substituting defaults for any non-positive limits.
func NewBudget(cfg config.Content, redactor Redactor) *Budget {
	def := config.DefaultContent()
	if cfg.MaxItemBytes <= 0 {
		cfg.MaxItemBytes = def.MaxItemBytes
	}
	if cfg.MaxItemsPerResource <= 0 {
		cfg.MaxItemsPerResource = def.MaxItemsPerResource
	}
	if cfg.MaxServiceBytes <= 0 {
		cfg.MaxServiceBytes = def.MaxServiceBytes
	}
	if cfg.MaxSamplePoints <= 0 {
		cfg.MaxSamplePoints = def.MaxSamplePoints
	}
	return &Budget{
		cfg:           cfg,
		redactor:      redactor,
		resourceItems: make(map[string]int),
		reasonSeen:    make(map[string]bool),
	}
}

// ServiceLimitReached reports whether the per-service byte budget has been exhausted.
func (b *Budget) ServiceLimitReached() bool {
	if b == nil {
		return false
	}
	return b.serviceBytes >= b.cfg.MaxServiceBytes
}

// ClaimResourceItem reserves one item slot under resourceKey, returning false
// and recording truncation if max_items_per_resource or max_service_bytes is reached.
func (b *Budget) ClaimResourceItem(resourceKey string) (bool, string) {
	if b.serviceBytes >= b.cfg.MaxServiceBytes {
		reason := fmt.Sprintf("content service byte limit (%d) reached", b.cfg.MaxServiceBytes)
		b.MarkTruncated(reason)
		return false, reason
	}
	if resourceKey != "" && b.resourceItems[resourceKey] >= b.cfg.MaxItemsPerResource {
		reason := fmt.Sprintf("%s reached max_items_per_resource (%d)", resourceKey, b.cfg.MaxItemsPerResource)
		b.MarkTruncated(reason)
		return false, reason
	}
	if resourceKey != "" {
		b.resourceItems[resourceKey]++
	}
	return true, ""
}

// Add bounds, hashes, validates, and stores one content item. Empty bodies are skipped.
func (b *Budget) Add(in RecordInput) (Record, bool, error) {
	if in.Body == "" {
		return Record{}, false, nil
	}
	remaining := b.cfg.MaxServiceBytes - b.serviceBytes
	if remaining <= 0 {
		b.MarkTruncated(fmt.Sprintf("content service byte limit (%d) reached", b.cfg.MaxServiceBytes))
		return Record{}, false, nil
	}

	origBytes := int64(len(in.Body))
	body := in.Body
	var found []Finding
	if b.redactor != nil {
		body, found = b.redactor(body)
	}

	limit := b.cfg.MaxItemBytes
	reason := ""
	if remaining < limit {
		limit = remaining
		reason = fmt.Sprintf("truncated at max_service_bytes (%d)", b.cfg.MaxServiceBytes)
	} else {
		reason = fmt.Sprintf("truncated at max_item_bytes (%d)", b.cfg.MaxItemBytes)
	}

	truncated := false
	truncateReason := ""
	if int64(len(body)) > limit {
		cut := int(limit)
		for cut > 0 && !utf8.RuneStart(body[cut]) {
			cut--
		}
		if cut == 0 {
			b.MarkTruncated(reason)
			return Record{}, false, nil
		}
		body = body[:cut]
		truncated = true
		truncateReason = reason
		b.MarkTruncated(reason)
	}

	sum := sha256.Sum256([]byte(body))
	obsTime := in.ObservedAt
	if obsTime.IsZero() {
		obsTime = time.Now().UTC()
	}

	rec := Record{
		SchemaVersion:   SchemaVersion,
		DeploymentScope: in.DeploymentScope,
		ScanID:          in.ScanID,
		VantageKey:      in.VantageKey,
		ServiceID:       in.ServiceID,
		ResourceID:      in.ResourceID,
		Surface:         in.Surface,
		CheckID:         in.CheckID,
		Source:          evidence.SanitizeURL(in.Source),
		Kind:            in.Kind,
		Location:        in.Location,
		MediaType:       in.MediaType,
		ObservedAt:      obsTime.UTC().Format(time.RFC3339),
		Body:            body,
		BodyBytes:       int64(len(body)),
		OriginalBytes:   origBytes,
		BodySHA256:      hex.EncodeToString(sum[:]),
		Truncated:       truncated,
		TruncateReason:  truncateReason,
	}
	if err := rec.Validate(); err != nil {
		return Record{}, false, err
	}

	b.serviceBytes += rec.BodyBytes
	b.records = append(b.records, rec)
	for _, f := range found {
		f.Location = in.Location
		b.findings = append(b.findings, f)
	}
	return rec, true, nil
}

// Findings returns the secret findings recorded for stored items, in
// insertion order. Items rejected by limits are never scanned-and-kept, so
// they carry no findings.
func (b *Budget) Findings() []Finding { return append([]Finding(nil), b.findings...) }

// SecretTypes returns the sorted, de-duplicated detector types that matched
// in stored items.
func (b *Budget) SecretTypes() []string {
	seen := make(map[string]bool, len(b.findings))
	var types []string
	for _, f := range b.findings {
		if !seen[f.Type] {
			seen[f.Type] = true
			types = append(types, f.Type)
		}
	}
	sort.Strings(types)
	return types
}

// ExposureDetails renders findings for evidence details: type, location, and
// line. It never carries a secret value.
func ExposureDetails(findings []Finding) []any {
	details := make([]any, 0, len(findings))
	for _, f := range findings {
		details = append(details, map[string]any{"type": f.Type, "location": f.Location, "line": f.Line})
	}
	return details
}

// MarkTruncated records that a content limit stopped or shortened collection.
func (b *Budget) MarkTruncated(reason string) {
	b.truncated = true
	reason = strings.TrimSpace(reason)
	if reason != "" && !b.reasonSeen[reason] {
		b.reasonSeen[reason] = true
		b.reasons = append(b.reasons, reason)
	}
}

func (b *Budget) Records() []Record { return append([]Record(nil), b.records...) }
func (b *Budget) Bytes() int64      { return b.serviceBytes }
func (b *Budget) Truncated() bool   { return b.truncated }
func (b *Budget) Reasons() []string { return append([]string(nil), b.reasons...) }

var binaryMIMETypes = map[string]bool{
	"application/octet-stream":     true,
	"application/zip":              true,
	"application/gzip":             true,
	"application/x-gzip":           true,
	"application/x-tar":            true,
	"application/x-bzip2":          true,
	"application/x-xz":             true,
	"application/pdf":              true,
	"application/wasm":             true,
	"application/x-executable":     true,
	"application/x-sharedlib":      true,
	"application/x-pickle":         true,
	"application/x-sqlite3":        true,
	"application/vnd.apache.arrow": true,
	"application/parquet":          true,
}

var binaryExtensions = map[string]bool{
	".gguf": true, ".bin": true, ".pt": true, ".pth": true, ".safetensors": true,
	".onnx": true, ".pb": true, ".tflite": true, ".ckpt": true, ".h5": true,
	".hdf5": true, ".pkl": true, ".pickle": true, ".npy": true, ".npz": true,
	".parquet": true, ".arrow": true, ".feather": true, ".so": true, ".dylib": true,
	".dll": true, ".exe": true, ".wasm": true, ".tar": true, ".gz": true,
	".tgz": true, ".zip": true, ".bz2": true, ".xz": true, ".7z": true,
	".rar": true, ".png": true, ".jpg": true, ".jpeg": true, ".gif": true,
	".webp": true, ".ico": true, ".pdf": true, ".woff": true, ".woff2": true,
	".ttf": true, ".otf": true, ".mp3": true, ".mp4": true, ".wav": true,
	".sqlite": true, ".db": true,
}

// IsBinaryContent reports whether a file path/URI or MIME type designates a
// binary blob or model weights that must never be fetched in the content tier.
func IsBinaryContent(nameOrPath, mimeType string) bool {
	if mimeType != "" {
		mt := strings.ToLower(strings.TrimSpace(strings.Split(mimeType, ";")[0]))
		for _, prefix := range []string{"image/", "audio/", "video/", "font/"} {
			if strings.HasPrefix(mt, prefix) {
				return true
			}
		}
		if binaryMIMETypes[mt] {
			return true
		}
	}

	cleaned := strings.TrimSpace(nameOrPath)
	if u, err := url.Parse(cleaned); err == nil && u.Path != "" {
		cleaned = u.Path
	}
	ext := strings.ToLower(path.Ext(cleaned))
	return binaryExtensions[ext]
}

// LooksBinary reports whether data contains NUL bytes or non-UTF-8 sequences,
// preventing binary blobs served with a missing MIME type from entering .content.jsonl.
func LooksBinary(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	if bytes.IndexByte(data, 0) >= 0 {
		return true
	}
	return !utf8.Valid(data)
}
