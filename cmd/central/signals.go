// Signal stream (M2.9): structured JSON, one line per signal, to a file
// sink -- "a trivial script consumer can parse and act" is the whole bar
// (`tail -f signals.jsonl | jq`). No webhook delivery in this pass; the
// file sink already proves the signal shape and the detection logic, which
// is what's actually in question. A ring buffer feeds the dashboard so a
// reviewer sees signals without needing a second terminal.
package main

import (
	"bufio"
	"encoding/json"
	"log/slog"
	"os"
	"sync"
	"time"
)

type Signal struct {
	Type          string      `json:"type"` // spec_deviation | invariant_violation | denied_endpoint_observed
	FleetIdentity string      `json:"fleet_identity"`
	Instance      string      `json:"instance"`
	Severity      string      `json:"severity"`
	Endpoint      EndpointRef `json:"endpoint,omitempty"`
	SpecReference string      `json:"spec_reference,omitempty"`
	Evidence      any         `json:"evidence"`
	At            string      `json:"at"`
}

const signalRingSize = 200

type SignalSink struct {
	mu   sync.Mutex
	file *os.File
	w    *bufio.Writer
	ring []Signal // most recent last
}

func newSignalSink(path string) (*SignalSink, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	return &SignalSink{file: f, w: bufio.NewWriter(f)}, nil
}

func (s *SignalSink) Emit(sig Signal) {
	sig.At = time.Now().UTC().Format(time.RFC3339)

	s.mu.Lock()
	defer s.mu.Unlock()

	line, err := json.Marshal(sig)
	if err != nil {
		slog.Error("marshal signal failed", "error", err)
		return
	}
	s.w.Write(line)
	s.w.WriteByte('\n')
	s.w.Flush()

	s.ring = append(s.ring, sig)
	if len(s.ring) > signalRingSize {
		s.ring = s.ring[len(s.ring)-signalRingSize:]
	}
	slog.Info("signal", "type", sig.Type, "fleet_identity", sig.FleetIdentity, "severity", sig.Severity)
}

// Recent returns the most recent signals, newest first.
func (s *SignalSink) Recent() []Signal {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Signal, len(s.ring))
	for i, sig := range s.ring {
		out[len(s.ring)-1-i] = sig
	}
	return out
}
