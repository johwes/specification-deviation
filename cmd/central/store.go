// Proposal aggregation and drift/invariant detection (M2.3, M2.7, M2.8,
// M2.10). Discovery state is in-memory only -- restarting central loses
// the pending queue, which is an acceptable simplification for a PoC: the
// property actually being tested (node-side resilience) is M1's, already
// proven. What must survive a restart is the ratified decisions, and
// those are the git-backed store, not this.
package main

import (
	"strings"
	"sync"
	"time"
)

// RawEvent decodes both conn and raw_socket event shapes emitted by
// cmd/sensor -- fields irrelevant to a given type are simply left zero.
//
// Family and Protocol are `any`, not fixed types: conn events encode
// protocol/family as strings ("tcp"/"ipv4"), raw_socket events encode them
// as numbers (the raw socket(2) domain/protocol) -- same JSON keys,
// different types depending on which event carries them. Fixed types here
// broke decoding outright, found live against real sensor traffic (a
// synthetic local test had used "tcp" by hand for both event shapes,
// never exercising the real numeric raw_socket wire format): first
// "cannot unmarshal string into ... family", then, after fixing that,
// "cannot unmarshal number into ... protocol". protocolStr() is the
// typed accessor for the conn-event case, which is the only place this
// value needs to be a comparable string (decision lookups, grouping keys).
type RawEvent struct {
	Type          string `json:"type"`
	Instance      string `json:"instance"`
	FleetIdentity string `json:"fleet_identity"`
	Addr          string `json:"addr"`
	FQDN          string `json:"fqdn"`
	Port          uint16 `json:"port"`
	Protocol      any    `json:"protocol"`
	Comm          string `json:"comm"`
	ParentComm    string `json:"parent_comm"`
	Family        any    `json:"family"`
	SockType      int32  `json:"sock_type"`
	Signal        string `json:"signal"`
}

func (ev RawEvent) protocolStr() string {
	s, _ := ev.Protocol.(string)
	return s
}

type proposalKey struct {
	fleetIdentity string
	endpointValue string
	port          uint16
	protocol      string
}

type Proposal struct {
	FleetIdentity   string
	Endpoint        EndpointRef
	Port            uint16
	Protocol        string
	Instances       map[string]bool
	FirstSeen       time.Time
	LastSeen        time.Time
	Count           int
	SampleComm      string
	DirectToIP      bool // risk annotation: no FQDN observed for this endpoint
	ShellInitiated  bool // risk annotation: first seen from an interactive shell
	Suggested       bool // static seed match → suggested: allow
	SuggestedReason string
}

type Store struct {
	decisions *DecisionStore
	signals   *SignalSink
	seeds     *SeedStore

	mu        sync.Mutex
	proposals map[proposalKey]*Proposal
}

func newStore(decisions *DecisionStore, signals *SignalSink) *Store {
	return newStoreWithSeeds(decisions, signals, newSeedStore(nil))
}

func newStoreWithSeeds(decisions *DecisionStore, signals *SignalSink, seeds *SeedStore) *Store {
	return &Store{
		decisions: decisions,
		signals:   signals,
		seeds:     seeds,
		proposals: make(map[proposalKey]*Proposal),
	}
}

var shellComms = map[string]bool{"bash": true, "sh": true, "zsh": true, "dash": true}

func (s *Store) Ingest(events []RawEvent) {
	for _, ev := range events {
		switch ev.Type {
		case "conn":
			s.ingestConn(ev)
		case "raw_socket":
			s.ingestRawSocket(ev)
		}
	}
}

func (s *Store) ingestConn(ev RawEvent) {
	endpointType, endpointValue := "ip", ev.Addr
	if ev.FQDN != "" {
		endpointType, endpointValue = "fqdn", ev.FQDN
	}
	// Effective port/protocol for matching — normalize the BPF
	// sendmsg port=0 quirk for connected UDP (chronyd IPv6 shows 0).
	port := ev.Port
	proto := ev.protocolStr()
	if port == 0 && proto == "udp" && strings.Contains(strings.ToLower(ev.FleetIdentity), "chronyd") {
		port = 123
	}
	// NTP pool grouping under the pool's DNS name (e.g. time.aws.com).
	// All chronyd 123/udp traffic for the same declared pool collapses to
	// one proposal, even when the DNS cache missed and the endpoint is a
	// raw IP (egress blocked — connect() observed, no response).
	if s.seeds != nil {
		if group, ok := s.seeds.GroupFor(endpointValue, port, proto, ev.FleetIdentity); ok {
			endpointType, endpointValue = "group", group
		}
	}

	if dec, ok := s.decisions.Lookup(ev.FleetIdentity, endpointValue, port, proto); ok {
		if dec.Decision == "deny" {
			s.signals.Emit(Signal{
				Type:          "denied_endpoint_observed",
				FleetIdentity: ev.FleetIdentity,
				Instance:      ev.Instance,
				Severity:      "high",
				Endpoint:      EndpointRef{Type: endpointType, Value: endpointValue},
				SpecReference: "decision:" + ev.FleetIdentity,
				Evidence:      map[string]any{"process": ev.Comm, "port": ev.Port, "protocol": ev.Protocol},
			})
		}
		return // allowed traffic on an already-decided endpoint: nothing to do
	}

	// No decision for this exact endpoint. Record/refresh the proposal
	// (queue item either way), then decide whether its absence is drift
	// (workload already has a ratified baseline) or just Stage 1
	// discovery (workload has never been reviewed).
	key := proposalKey{ev.FleetIdentity, endpointValue, port, proto}

	s.mu.Lock()
	p, ok := s.proposals[key]
	if !ok {
		p = &Proposal{
			FleetIdentity:  ev.FleetIdentity,
			Endpoint:       EndpointRef{Type: endpointType, Value: endpointValue},
			Port:           port,
			Protocol:       proto,
			Instances:      make(map[string]bool),
			FirstSeen:      time.Now(),
			SampleComm:     ev.Comm,
			DirectToIP:     endpointType == "ip",
			ShellInitiated: shellComms[ev.ParentComm],
		}
		s.proposals[key] = p
	}
	p.Instances[ev.Instance] = true
	p.LastSeen = time.Now()
	p.Count++
	s.mu.Unlock()

	if s.decisions.HasAnyDecision(ev.FleetIdentity) {
		s.signals.Emit(Signal{
			Type:          "spec_deviation",
			FleetIdentity: ev.FleetIdentity,
			Instance:      ev.Instance,
			Severity:      "high",
			Endpoint:      EndpointRef{Type: endpointType, Value: endpointValue},
			SpecReference: "decision:" + ev.FleetIdentity,
			Evidence:      map[string]any{"process": ev.Comm, "port": port, "protocol": proto, "first_seen": p.FirstSeen},
		})
	}
}

// ingestRawSocket handles the one invariant this PoC actually built
// (M0.5): always-on, no ratification needed. The process-ancestry
// (shell-spawned-from-a-service) invariant from the demo script was
// deliberately left out of scope -- other tools (Falco) already cover it;
// see the M0 discussion. This substitutes the raw-socket invariant for
// that step of the demo.
func (s *Store) ingestRawSocket(ev RawEvent) {
	s.signals.Emit(Signal{
		Type:          "invariant_violation",
		FleetIdentity: ev.FleetIdentity,
		Instance:      ev.Instance,
		Severity:      "high",
		SpecReference: "invariant:raw-socket-creation",
		Evidence: map[string]any{
			"process": ev.Comm, "family": ev.Family, "sock_type": ev.SockType, "signal": ev.Signal,
		},
	})
}

// PendingProposals returns proposals with no ratified decision yet,
// grouped by fleet identity, for the review UI (M2.6). Suggested
// annotation is computed lazily here so Ingest stays cheap.
func (s *Store) PendingProposals() map[string][]*Proposal {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make(map[string][]*Proposal)
	for k, p := range s.proposals {
		if _, decided := s.decisions.Lookup(k.fleetIdentity, k.endpointValue, k.port, k.protocol); decided {
			continue
		}
		if s.seeds != nil {
			if ok, reason, _ := s.seeds.MatchesWithGroup(k.endpointValue, k.port, k.protocol, k.fleetIdentity); ok {
				p.Suggested = true
				p.SuggestedReason = reason
			} else {
				p.Suggested = false
				p.SuggestedReason = ""
			}
		}
		out[k.fleetIdentity] = append(out[k.fleetIdentity], p)
	}
	return out
}

// Dismiss, DismissWorkload, and DismissAll are housekeeping, not
// ratification: they remove entries from the pending queue without
// creating a decision. No git commit, nothing is allowed or denied -- if
// the same traffic recurs, it simply reappears as a fresh proposal next
// time. This is deliberately weaker than a real decision (backlog.md's
// standing rule: "learned data never authorizes itself"); it exists purely
// to let a reviewer clear noise they don't want to look at right now.

func (s *Store) Dismiss(fleetIdentity, endpointValue string, port uint16, protocol string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.proposals, proposalKey{fleetIdentity, endpointValue, port, protocol})
}

func (s *Store) DismissWorkload(fleetIdentity string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.proposals {
		if k.fleetIdentity == fleetIdentity {
			delete(s.proposals, k)
		}
	}
}

func (s *Store) DismissAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.proposals = make(map[proposalKey]*Proposal)
}
