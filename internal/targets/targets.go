// Package targets prepares authorized target input without DNS resolution or traffic.
package targets

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"strings"
)

const (
	// HardMaxTargets caps raw expansion, including duplicates, before exclusions.
	HardMaxTargets  = 65536
	MaxInputEntries = 65536
	MaxInputFiles   = 128
	// MaxInputBytes caps the aggregate size of all input files.
	MaxInputBytes = 1 << 20
)

type Input struct {
	Entries      []string
	Files        []string
	Exclude      []string
	ExcludeFiles []string
	MaxTargets   int
}

type entry struct{ value, source string }

// Prepare returns a lexically sorted, deduplicated target list. Exclusions are
// exact normalized names/addresses or IP prefixes; they never imply DNS matches.
// CIDRs include every address. Invalid input fails atomically with no partial list.
func Prepare(in Input) ([]string, error) {
	if in.MaxTargets < 1 || in.MaxTargets > HardMaxTargets {
		return nil, fmt.Errorf("max_targets must be between 1 and %d", HardMaxTargets)
	}
	if len(in.Entries)+len(in.Exclude)+len(in.Files)+len(in.ExcludeFiles) > MaxInputEntries {
		return nil, fmt.Errorf("too many input entries (maximum %d)", MaxInputEntries)
	}
	if len(in.Files)+len(in.ExcludeFiles) > MaxInputFiles {
		return nil, fmt.Errorf("too many input files (maximum %d)", MaxInputFiles)
	}
	count, bytes := 0, 0
	includes, err := readEntries(in.Entries, in.Files, "targets", &count, &bytes)
	if err != nil {
		return nil, err
	}
	excludes, err := readEntries(in.Exclude, in.ExcludeFiles, "exclude", &count, &bytes)
	if err != nil {
		return nil, err
	}
	excludedHosts := make(map[string]bool)
	excludedPrefixes := make(map[netip.Prefix]bool)
	for _, e := range excludes {
		host, prefix, err := parse(e.value, true)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.source, err)
		}
		if prefix.IsValid() {
			excludedPrefixes[prefix] = true
		} else {
			excludedHosts[host] = true
		}
	}
	result := make(map[string]bool)
	expanded := 0
	add := func(host string) error {
		expanded++
		if expanded > in.MaxTargets {
			return fmt.Errorf("raw target expansion exceeds max_targets %d (before deduplication/exclusions)", in.MaxTargets)
		}
		result[host] = true
		return nil
	}
	for _, e := range includes {
		host, prefix, err := parse(e.value, false)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.source, err)
		}
		if !prefix.IsValid() {
			if err := add(host); err != nil {
				return nil, fmt.Errorf("%s: %w", e.source, err)
			}
			continue
		}
		bits := prefix.Addr().BitLen() - prefix.Bits()
		// Avoid shifts/overflow and reject enormous IPv6 ranges before iteration.
		if bits > 16 || (1<<uint(bits)) > in.MaxTargets-expanded {
			return nil, fmt.Errorf("%s: CIDR expansion exceeds remaining max_targets %d (before exclusions)", e.source, in.MaxTargets-expanded)
		}
		n := 1 << uint(bits)
		addr := prefix.Addr()
		for i := 0; i < n; i++ {
			if unsafeAddress(addr) {
				return nil, fmt.Errorf("%s: CIDR contains unspecified or multicast address", e.source)
			}
			if err := add(addr.String()); err != nil {
				return nil, err
			}
			addr = addr.Next()
		}
	}
	out := make([]string, 0, len(result))
	for host := range result {
		if excludedHosts[host] {
			continue
		}
		excluded := false
		if addr, err := netip.ParseAddr(host); err == nil {
			// Prefix lookup is bounded by address width, not number of exclusions.
			for bits := 0; bits <= addr.BitLen(); bits++ {
				if excludedPrefixes[netip.PrefixFrom(addr, bits).Masked()] {
					excluded = true
					break
				}
			}
		}
		if !excluded {
			out = append(out, host)
		}
	}
	sort.Strings(out)
	return out, nil
}

func readEntries(values, files []string, label string, count, bytes *int) ([]entry, error) {
	out := make([]entry, 0, len(values))
	add := func(value, source string) error {
		(*count)++
		if *count > MaxInputEntries {
			return fmt.Errorf("too many input entries (maximum %d)", MaxInputEntries)
		}
		out = append(out, entry{value, source})
		return nil
	}
	for i, value := range values {
		if err := add(value, fmt.Sprintf("%s[%d]", label, i)); err != nil {
			return nil, err
		}
	}
	for _, path := range files {
		info, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("stat %s file: %w", label, err)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("%s file must be a regular file: %s", label, path)
		}
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("open %s file: %w", label, err)
		}
		info, err = f.Stat()
		if err != nil || !info.Mode().IsRegular() {
			_ = f.Close()
			return nil, fmt.Errorf("%s file must be a readable regular file: %s", label, path)
		}
		remaining := MaxInputBytes - *bytes
		data, err := io.ReadAll(io.LimitReader(f, int64(remaining+1)))
		closeErr := f.Close()
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close %s: %w", path, closeErr)
		}
		*bytes += len(data)
		if *bytes > MaxInputBytes {
			return nil, fmt.Errorf("input files exceed aggregate %d byte limit", MaxInputBytes)
		}
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		scanner.Buffer(make([]byte, 1024), 4096)
		line := 0
		for scanner.Scan() {
			line++
			value := strings.TrimSpace(strings.SplitN(scanner.Text(), "#", 2)[0])
			if value == "" {
				continue
			}
			if err := add(value, fmt.Sprintf("%s:%d", path, line)); err != nil {
				return nil, err
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("%s:%d: input line too long or unreadable: %w", path, line+1, err)
		}
	}
	return out, nil
}

func parse(value string, exclusion bool) (string, netip.Prefix, error) {
	value = strings.TrimSpace(value)
	if strings.Contains(value, "/") {
		p, err := netip.ParsePrefix(value)
		if err != nil || p.Addr().Is4In6() {
			return "", netip.Prefix{}, fmt.Errorf("invalid CIDR (IPv4-mapped prefixes are not supported)")
		}
		if p != p.Masked() {
			return "", netip.Prefix{}, fmt.Errorf("CIDR has host bits set; specify its network address explicitly")
		}
		if !exclusion && unsafeAddress(p.Addr()) {
			return "", netip.Prefix{}, fmt.Errorf("unspecified or multicast target address is not allowed")
		}
		return "", p, nil
	}
	host, err := NormalizeHost(value)
	if err != nil {
		return "", netip.Prefix{}, err
	}
	return host, netip.Prefix{}, nil
}

func unsafeAddress(addr netip.Addr) bool { return addr.IsUnspecified() || addr.IsMulticast() }

// NormalizeHost accepts unscoped IP literals and ASCII FQDNs only. It performs
// syntactic canonicalization, never DNS resolution or hostname/IP identity merging.
func NormalizeHost(value string) (string, error) {
	value = strings.TrimSpace(value)
	if addr, err := netip.ParseAddr(value); err == nil {
		if addr.Zone() != "" {
			return "", fmt.Errorf("scoped IPv6 targets are not supported")
		}
		addr = addr.Unmap()
		if unsafeAddress(addr) {
			return "", fmt.Errorf("unspecified or multicast target address is not allowed")
		}
		return addr.String(), nil
	}
	for _, ch := range value {
		if ch > 127 {
			return "", fmt.Errorf("FQDN must be ASCII; use explicit punycode for internationalized names")
		}
	}
	name := strings.ToLower(strings.TrimSuffix(value, "."))
	if len(name) > 253 || !strings.Contains(name, ".") {
		return "", fmt.Errorf("target must be an IP literal, CIDR, or fully qualified ASCII hostname")
	}
	tld := name[strings.LastIndexByte(name, '.')+1:]
	if strings.HasPrefix(tld, "0x") || strings.Trim(tld, "0123456789") == "" {
		return "", fmt.Errorf("invalid numeric IP address")
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid FQDN label")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", fmt.Errorf("FQDN must contain only ASCII letters, digits, and hyphens; URLs, ports, credentials, and wildcards are not accepted")
			}
		}
	}
	return name, nil
}
