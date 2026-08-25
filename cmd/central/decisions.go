// Git-backed decision store (M2.5). Every ratification is a real `git
// commit` -- the repo history is the audit trail, `git log`/`git show` is
// the revert/attribution tool, for free. Schema follows
// architecture-specification.md §6.3, minus the self-referential `version`
// field: a decision's version is the commit that introduced or changed it
// (`git log -- <path>`), not something to store redundantly inside the
// file itself.
package main

import (
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

type Decision struct {
	FleetIdentity string      `json:"fleet_identity"`
	Endpoint      EndpointRef `json:"endpoint"`
	Port          uint16      `json:"port"`
	Protocol      string      `json:"protocol"`
	Decision      string      `json:"decision"` // "allow" | "deny"
	Owner         string      `json:"owner,omitempty"`
	DecidedBy     string      `json:"decided_by"`
	DecidedAt     string      `json:"decided_at"`
	Source        string      `json:"source"` // "learned"
}

type EndpointRef struct {
	Type  string `json:"type"` // "fqdn" | "ip"
	Value string `json:"value"`
}

// decisionKey identifies one (fleet_identity, endpoint, port, protocol)
// decision -- the same granularity the architecture spec ratifies at.
type decisionKey struct {
	fleetIdentity string
	endpointValue string
	port          uint16
	protocol      string
}

func keyFor(d Decision) decisionKey {
	return decisionKey{d.FleetIdentity, d.Endpoint.Value, d.Port, d.Protocol}
}

var unsafePathChars = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

func sanitize(s string) string {
	return unsafePathChars.ReplaceAllString(s, "_")
}

// pathFor returns a stable, human-browsable file path for a decision: the
// fleet identity as a directory, a short hash of the rest as the filename
// so two decisions for the same workload never collide, and the whole
// thing stays legible under `find`/`ls` for someone auditing the repo by
// hand.
func pathFor(k decisionKey) string {
	h := sha1.Sum([]byte(fmt.Sprintf("%s|%d|%s", k.endpointValue, k.port, k.protocol)))
	return filepath.Join(sanitize(k.fleetIdentity), fmt.Sprintf("%x.json", h[:6]))
}

// DecisionStore is a directory of JSON files under git version control.
// Reads are served from an in-memory cache; writes go to disk, get
// committed, then update the cache -- so a decision is never "ratified"
// without a corresponding commit existing.
type DecisionStore struct {
	repoPath string

	mu    sync.RWMutex
	cache map[decisionKey]Decision
}

func newDecisionStore(repoPath string) (*DecisionStore, error) {
	if err := os.MkdirAll(repoPath, 0o755); err != nil {
		return nil, err
	}
	if _, err := os.Stat(filepath.Join(repoPath, ".git")); os.IsNotExist(err) {
		for _, args := range [][]string{
			{"init"},
			{"config", "user.name", "specdev-central"},
			{"config", "user.email", "central@specification-deviation.local"},
		} {
			if out, err := gitCmd(repoPath, args...); err != nil {
				return nil, fmt.Errorf("git %v: %w (%s)", args, err, out)
			}
		}
	}

	s := &DecisionStore{repoPath: repoPath, cache: make(map[decisionKey]Decision)}
	if err := s.loadAll(); err != nil {
		return nil, err
	}
	return s, nil
}

func gitCmd(repoPath string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", repoPath}, args...)...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (s *DecisionStore) loadAll() error {
	return filepath.WalkDir(s.repoPath, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".json") {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var dec Decision
		if err := json.Unmarshal(data, &dec); err != nil {
			return fmt.Errorf("decode %s: %w", path, err)
		}
		s.cache[keyFor(dec)] = dec
		return nil
	})
}

// Lookup returns the decision for this exact endpoint, if one has been
// ratified.
func (s *DecisionStore) Lookup(fleetIdentity, endpointValue string, port uint16, protocol string) (Decision, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.cache[decisionKey{fleetIdentity, endpointValue, port, protocol}]
	return d, ok
}

// HasAnyDecision reports whether fleetIdentity has been ratified at all --
// the signal for "this workload has an active spec; a new endpoint is
// drift" vs. "this workload has never been reviewed; a new endpoint is
// just Stage 1 discovery" (architecture-specification.md §11).
func (s *DecisionStore) HasAnyDecision(fleetIdentity string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for k := range s.cache {
		if k.fleetIdentity == fleetIdentity {
			return true
		}
	}
	return false
}

// Ratify writes d to disk and commits it -- the decision does not exist
// until the commit succeeds.
func (s *DecisionStore) Ratify(d Decision) error {
	k := keyFor(d)
	relPath := pathFor(k)
	fullPath := filepath.Join(s.repoPath, relPath)

	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(fullPath, data, 0o644); err != nil {
		return err
	}

	if out, err := gitCmd(s.repoPath, "add", relPath); err != nil {
		return fmt.Errorf("git add: %w (%s)", err, out)
	}
	msg := fmt.Sprintf("%s: %s %s:%d/%s (%s)", d.DecidedBy, d.Decision, d.Endpoint.Value, d.Port, d.Protocol, d.FleetIdentity)
	if out, err := gitCmd(s.repoPath, "commit", "-m", msg); err != nil {
		return fmt.Errorf("git commit: %w (%s)", err, out)
	}

	s.mu.Lock()
	s.cache[k] = d
	s.mu.Unlock()
	return nil
}
