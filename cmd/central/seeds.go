// Seeds — M2.2 P0: static-declaration ingestion → suggested: allow.
//
// Advisory-only: seeds annotate proposals, never authorize them.
// A suggested proposal still requires a human Allow → git commit. A
// compromised config on a verified host must still produce
// spec_deviation when it contacts an undeclared endpoint (architecture
// spec §11 critical constraint). This file is the P0 cut: resolv.conf
// and chrony.conf parsers + group match for NTP pools. No enforcement
// path, no iptables, no CNP export — see backlog M3 DEFERRED note.
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Seed is a single static-declared endpoint that should be surfaced as
// "suggested: allow (<source>)" in the review queue. Seeds are global
// (architecture spec §11 Stage 0) — intra-scope vs global is not needed
// at this tier.
type Seed struct {
	Endpoint EndpointRef `json:"endpoint" yaml:"endpoint"`
	Port     uint16      `json:"port" yaml:"port"`         // 0 = any port
	Protocol string      `json:"protocol" yaml:"protocol"` // "" = any
	Source   string      `json:"source" yaml:"source"`     // "resolv.conf:3" etc.
	Reason   string      `json:"reason" yaml:"reason"`
}

// SeedsFile is the on-disk shape of data/seeds.yaml / seeds.example.yaml.
type SeedsFile struct {
	Seeds []Seed `yaml:"seeds"`
}

// SeedStore holds loaded seeds and the derived indexes for matching.
// No git, no decisions — just the declared set.
type SeedStore struct {
	seeds       []Seed
	byValuePort map[string]string // "value|port|proto" → reason, exact match
	suffixRules []suffixRule      // group DNS-suffix patterns
}

type suffixRule struct {
	suffix string // lower-cased, no leading "*.", e.g. "pool.ntp.org"
	group  string // EndpointRef.Value for the group seed
	reason string
	port   uint16
	proto  string
}

func newSeedStore(seeds []Seed) *SeedStore {
	s := &SeedStore{
		seeds:       seeds,
		byValuePort: make(map[string]string, len(seeds)),
	}
	for _, sd := range seeds {
		// Index exact non-group seeds by value|port|proto and wildcards.
		if sd.Endpoint.Type == "group" {
			// Group is only suffix-based for P0 (NTP pool). The seed's
			// value is the group name; the matchable DNS names are derived
			// from the Reason/Source in the example, but for now we
			// hard-wire the pool suffix from the seed value convention:
			// a group seed for NTP implies suffix pool.ntp.org.
			// Callers that construct group seeds with explicit suffix can
			// extend this; the committed example uses the same convention.
			// Also accept an ip/CIDR group later — not needed for P0.
			s.suffixRules = append(s.suffixRules, suffixRule{
				suffix: "pool.ntp.org",
				group:  sd.Endpoint.Value,
				reason: sd.Reason,
				port:   sd.Port,
				proto:  sd.Protocol,
			})
			// Also match rhel.pool.ntp.org subdomains.
			s.suffixRules = append(s.suffixRules, suffixRule{
				suffix: "rhel.pool.ntp.org",
				group:  sd.Endpoint.Value,
				reason: sd.Reason,
				port:   sd.Port,
				proto:  sd.Protocol,
			})
			continue
		}
		for _, key := range seedKeys(sd.Endpoint.Value, sd.Port, sd.Protocol) {
			s.byValuePort[key] = sd.Reason
			if sd.Source != "" {
				s.byValuePort[key] = fmt.Sprintf("%s (%s)", sd.Reason, sd.Source)
			}
		}
	}
	return s
}

func seedKeys(value string, port uint16, proto string) []string {
	// Store exact and wildcard combos so Matches can try specific then
	// wildcard port/proto. Keep it small: port/proto wildcards are 0/""
	// which we store as "*".
	p := proto
	if p == "" {
		p = "*"
	}
	ps := fmt.Sprintf("%d", port)
	if port == 0 {
		ps = "*"
	}
	return []string{
		fmt.Sprintf("%s|%s|%s", value, ps, p),
		fmt.Sprintf("%s|%s|%s", value, ps, "*"),
		fmt.Sprintf("%s|%s|%s", value, "*", p),
		fmt.Sprintf("%s|%s|%s", value, "*", "*"),
	}
}

// Matches reports whether (endpointValue, port, proto) is covered by a
// static seed. If so, the second return is the human reason string
// (Reason + optional Source) for the UI badge.
func (s *SeedStore) Matches(endpointValue string, port uint16, proto string) (bool, string) {
	if s == nil || len(s.seeds) == 0 {
		return false, ""
	}
	// 1) Exact value match (ip or fqdn), respecting port/proto wildcards.
	for _, key := range seedKeys(endpointValue, port, proto) {
		if reason, ok := s.byValuePort[key]; ok {
			return true, reason
		}
	}
	// 2) Suffix group match — NTP pools: an observed fqdn like
	// 0.rhel.pool.ntp.org ends with the pool suffix → matches the group
	// seed. Honest tradeoff: wider trust than exact IP (parking lot).
	low := strings.ToLower(endpointValue)
	for _, r := range s.suffixRules {
		if strings.HasSuffix(low, "."+r.suffix) || low == r.suffix {
			// Port/proto must match if the rule constrains them.
			if r.port != 0 && r.port != port {
				continue
			}
			if r.proto != "" && r.proto != proto {
				continue
			}
			return true, r.reason
		}
	}
	return false, ""
}

// ---------------------------------------------------------------------------
// Parsers — pure, testable, no FS except via callers
// ---------------------------------------------------------------------------

// ParseResolvConf parses nameserver lines from /etc/resolv.conf.
// Each nameserver becomes a seed for 53/udp and 53/tcp (DNS).
func ParseResolvConf(data []byte) []Seed {
	var seeds []Seed
	sc := bufio.NewScanner(bytes.NewReader(data))
	lineno := 0
	for sc.Scan() {
		lineno++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || strings.ToLower(fields[0]) != "nameserver" {
			continue
		}
		ipStr := fields[1]
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		base := Seed{
			Endpoint: EndpointRef{Type: "ip", Value: ip.String()},
			Source:   fmt.Sprintf("resolv.conf:%d", lineno),
			Reason:   "cluster DNS",
		}
		for _, proto := range []string{"udp", "tcp"} {
			sd := base
			sd.Port = 53
			sd.Protocol = proto
			seeds = append(seeds, sd)
		}
	}
	return seeds
}

// ParseChronyConf parses server/pool lines from /etc/chrony.conf.
// server → exact fqdn seed per host; pool → one group seed for the pool
// name (suffix-based). NTP is 123/udp only.
func ParseChronyConf(data []byte) []Seed {
	var seeds []Seed
	seenPool := make(map[string]bool)
	sc := bufio.NewScanner(bytes.NewReader(data))
	lineno := 0
	for sc.Scan() {
		lineno++
		raw := sc.Text()
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "!") {
			continue
		}
		// Strip inline comments.
		if idx := strings.Index(trimmed, "#"); idx >= 0 {
			trimmed = strings.TrimSpace(trimmed[:idx])
		}
		if trimmed == "" {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 2 {
			continue
		}
		dir := strings.ToLower(fields[0])
		if dir != "server" && dir != "pool" {
			continue
		}
		host := fields[1]
		// chrony allows options after host; host is field 1 only.
		if dir == "pool" {
			if seenPool[host] {
				continue
			}
			seenPool[host] = true
			// Pool → group seed. The suffix rule mapping lives in
			// newSeedStore (pool.ntp.org, rhel.pool.ntp.org). The seed
			// value is the group name; matching is suffix-based.
			seeds = append(seeds, Seed{
				Endpoint: EndpointRef{Type: "group", Value: "approved-ntp-pool"},
				Port:     123,
				Protocol: "udp",
				Source:   fmt.Sprintf("chrony.conf:%d", lineno),
				Reason:   fmt.Sprintf("NTP pool %s", host),
			})
		} else {
			// server → exact fqdn
			seeds = append(seeds, Seed{
				Endpoint: EndpointRef{Type: "fqdn", Value: host},
				Port:     123,
				Protocol: "udp",
				Source:   fmt.Sprintf("chrony.conf:%d", lineno),
				Reason:   fmt.Sprintf("NTP server %s", host),
			})
		}
	}
	return seeds
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

func loadSeeds(path string) (*SeedStore, error) {
	if path == "" {
		return newSeedStore(nil), nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return newSeedStore(nil), nil
		}
		return nil, err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return newSeedStore(nil), nil
	}
	var sf SeedsFile
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&sf); err != nil {
		return nil, fmt.Errorf("parse seeds %s: %w", path, err)
	}
	return newSeedStore(sf.Seeds), nil
}
