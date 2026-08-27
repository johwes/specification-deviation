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
		if sd.Endpoint.Type == "group" {
			// Group seeds are per-pool DNS names (e.g. time.aws.com,
			// 2.rhel.pool.ntp.org) from chrony.conf pool lines. The
			// observed endpoint may be the pool name itself or a
			// subdomain/round-robin member, or — when the DNS cache
			// missed — a raw IP from chronyd. Suffix matching covers the
			// first two; the IP case is handled in GroupFor with
			// fleet-aware fallback for port 123/udp.
			suffix := strings.ToLower(sd.Endpoint.Value)
			reason := sd.Reason
			if sd.Source != "" {
				reason = fmt.Sprintf("%s (%s)", sd.Reason, sd.Source)
			}
			s.suffixRules = append(s.suffixRules, suffixRule{
				suffix: suffix,
				group:  sd.Endpoint.Value,
				reason: reason,
				port:   sd.Port,
				proto:  sd.Protocol,
			})
			// Exact group value should also be directly suggested.
			for _, key := range seedKeys(sd.Endpoint.Value, sd.Port, sd.Protocol) {
				s.byValuePort[key] = reason
			}
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
	ok, reason, _ := s.MatchesWithGroup(endpointValue, port, proto, "")
	return ok, reason
}

// MatchesWithGroup is Matches but fleet-aware for the NTP pool case
// where chronyd produced a direct-to-ip endpoint (no FQDN) because the
// DNS cache missed before connect. In that case any 123/udp traffic
// from chronyd is considered part of its declared pool group.
func (s *SeedStore) MatchesWithGroup(endpointValue string, port uint16, proto string, fleet string) (bool, string, string) {
	if s == nil || len(s.seeds) == 0 {
		return false, "", ""
	}
	// 1) Exact value match (ip or fqdn), respecting port/proto wildcards.
	for _, key := range seedKeys(endpointValue, port, proto) {
		if reason, ok := s.byValuePort[key]; ok {
			return true, reason, ""
		}
	}
	// 2) Suffix group match — pool host or its subdomains.
	low := strings.ToLower(endpointValue)
	for _, r := range s.suffixRules {
		if strings.HasSuffix(low, "."+r.suffix) || low == r.suffix {
			if r.port != 0 && port != 0 && r.port != port {
				continue
			}
			if r.proto != "" && r.proto != proto {
				continue
			}
			return true, r.reason, r.group
		}
	}
	// 3) Fleet-aware IP fallback for blocked NTP: chronyd 123/udp
	// direct-to-ip that missed the DNS cache → still part of its pool.
	// Group is the pool's DNS name (e.g. time.aws.com), not an IP.
	// Also handles IPv6 and the BPF sendmsg port=0 quirk for connected
	// UDP (port 0 observed for chronyd sendmsg, not just 123).
	if (port == 123 || port == 0) && proto == "udp" && strings.Contains(strings.ToLower(fleet), "chronyd") {
		// Only for IP endpoints (no FQDN) that didn't match above.
		if net.ParseIP(endpointValue) != nil {
			for _, r := range s.suffixRules {
				if r.port == 123 && (r.proto == "udp" || r.proto == "") {
					// Wider trust than exact IP — grouped under pool name.
					return true, r.reason + " (grouped pool, egress blocked — connect() observed)", r.group
				}
			}
		}
	}
	return false, "", ""
}

// GroupFor returns the group name for an endpoint that belongs to a
// pool, if any, for pre-keying proposals under the pool name.
func (s *SeedStore) GroupFor(endpointValue string, port uint16, proto string, fleet string) (string, bool) {
	_, _, group := s.MatchesWithGroup(endpointValue, port, proto, fleet)
	if group != "" {
		return group, true
	}
	// For IP fallback, MatchesWithGroup already returned group via
	// the fleet-aware path, so we also need to surface it for grouping.
	// The above already handles it; exact+suffix also returned group.
	return "", false
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
			// Pool → group seed keyed by the pool's DNS name. This lets
			// all round-robin NTP traffic for that pool collapse under
			// the pool name, including direct-to-ip when egress is
			// blocked and the DNS cache missed before connect.
			seeds = append(seeds, Seed{
				Endpoint: EndpointRef{Type: "group", Value: host},
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
