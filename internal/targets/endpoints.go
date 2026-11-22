package targets

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// EndpointTarget represents an explicit pre-scanned host:port (with optional scheme)
// target supplied via endpoints_files. Scheme is "", "http", or "https".
type EndpointTarget struct {
	Host   string
	Port   int
	Scheme string
}

// String returns the canonical representation of the endpoint target.
func (e EndpointTarget) String() string {
	hostPort := net.JoinHostPort(e.Host, strconv.Itoa(e.Port))
	if e.Scheme != "" {
		return e.Scheme + "://" + hostPort
	}
	return hostPort
}

// PrepareEndpoints parses explicit host:port, [ipv6]:port, http://host:port, and
// https://host:port targets from entries/files, deduplicates them, and filters out
// hosts matching exact or CIDR exclusions.
func PrepareEndpoints(entries, files, exclude, excludeFiles []string, maxTargets int) ([]EndpointTarget, error) {
	if maxTargets < 1 || maxTargets > HardMaxTargets {
		return nil, fmt.Errorf("max_targets must be between 1 and %d", HardMaxTargets)
	}
	if len(entries)+len(exclude)+len(files)+len(excludeFiles) > MaxInputEntries {
		return nil, fmt.Errorf("too many input entries (maximum %d)", MaxInputEntries)
	}
	if len(files)+len(excludeFiles) > MaxInputFiles {
		return nil, fmt.Errorf("too many input files (maximum %d)", MaxInputFiles)
	}
	count, bytes := 0, 0
	includes, err := readEntries(entries, files, "endpoints", &count, &bytes)
	if err != nil {
		return nil, err
	}
	excludes, err := readEntries(exclude, excludeFiles, "exclude", &count, &bytes)
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

	seen := make(map[EndpointTarget]bool)
	parsedCount := 0
	for _, e := range includes {
		ep, err := parseEndpoint(e.value)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.source, err)
		}
		parsedCount++
		if parsedCount > maxTargets {
			return nil, fmt.Errorf("%s: endpoint targets exceed max_targets %d", e.source, maxTargets)
		}
		if isExcludedHost(ep.Host, excludedHosts, excludedPrefixes) {
			continue
		}
		seen[ep] = true
	}

	out := make([]EndpointTarget, 0, len(seen))
	for ep := range seen {
		out = append(out, ep)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].Scheme < out[j].Scheme
	})
	return out, nil
}

func isExcludedHost(host string, excludedHosts map[string]bool, excludedPrefixes map[netip.Prefix]bool) bool {
	if excludedHosts[host] {
		return true
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		for bits := 0; bits <= addr.BitLen(); bits++ {
			if excludedPrefixes[netip.PrefixFrom(addr, bits).Masked()] {
				return true
			}
		}
	}
	return false
}

func parseEndpoint(raw string) (EndpointTarget, error) {
	val := strings.TrimSpace(raw)
	if val == "" {
		return EndpointTarget{}, fmt.Errorf("endpoint cannot be empty")
	}

	var scheme, hostPort string
	if strings.Contains(val, "://") {
		u, err := url.Parse(val)
		if err != nil {
			return EndpointTarget{}, fmt.Errorf("invalid endpoint URL %q: %w", raw, err)
		}
		scheme = strings.ToLower(u.Scheme)
		if scheme != "http" && scheme != "https" {
			return EndpointTarget{}, fmt.Errorf("endpoint scheme must be http or https, got %q", u.Scheme)
		}
		if u.User != nil {
			return EndpointTarget{}, fmt.Errorf("endpoint must not contain credentials")
		}
		if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
			return EndpointTarget{}, fmt.Errorf("endpoint must not include path, query, or fragment")
		}
		hostPort = u.Host
	} else {
		if strings.ContainsAny(val, "/?#") {
			return EndpointTarget{}, fmt.Errorf("endpoint must be host:port without paths, queries, or fragments")
		}
		if strings.Contains(val, "@") {
			return EndpointTarget{}, fmt.Errorf("endpoint must not contain credentials")
		}
		hostPort = val
	}

	rawHost, rawPort, err := net.SplitHostPort(hostPort)
	if err != nil {
		return EndpointTarget{}, fmt.Errorf("endpoint %q must include explicit port: %w", raw, err)
	}
	host, err := NormalizeHost(rawHost)
	if err != nil {
		return EndpointTarget{}, fmt.Errorf("invalid endpoint host: %w", err)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil || port < 1 || port > 65535 {
		return EndpointTarget{}, fmt.Errorf("invalid endpoint port %q (must be 1-65535)", rawPort)
	}

	return EndpointTarget{Host: host, Port: port, Scheme: scheme}, nil
}
