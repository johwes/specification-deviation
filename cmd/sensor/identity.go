// Fleet identity resolution (M1.3-M1.5): maps a cgroup to a stable,
// instance-agnostic identity by reading /proc/<tgid>/cgroup for the unified
// (cgroup v2) hierarchy path and classifying it against the patterns in
// architecture-specification.md §5.1/§5.2.
//
// Resolved once per cgroup_id and cached -- cgroup_id is stable for the
// cgroup's lifetime (architecture-specification.md §5), so repeat lookups
// for the same workload are free after the first event. resolve() is only
// ever called from the single event-processing loop in run(), so the cache
// needs no locking.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

var (
	systemdServiceRE = regexp.MustCompile(`([^/]+\.service)$`)
	podmanScopeRE    = regexp.MustCompile(`libpod-([0-9a-f]{12,64})\.scope`)
	sessionScopeRE   = regexp.MustCompile(`session-[^/]+\.scope$`)
)

const maxIdentityCacheEntries = 65536

type identityResolver struct {
	cache map[uint64]string // cgroup_id -> fleet_identity
}

func newIdentityResolver() *identityResolver {
	return &identityResolver{cache: make(map[uint64]string)}
}

// resolve returns the fleet identity for cgroupID, resolving via
// /proc/<tgid>/cgroup on first sight and caching by cgroup_id thereafter.
// tgid is any process currently known to be in that cgroup -- best-effort,
// same spike-grade caveat as parentFromProc in main.go: a short-lived
// process can have already exited by the time this reads /proc, in which
// case the cgroup resolves to "unknown" and is retried on the next event.
func (r *identityResolver) resolve(cgroupID uint64, tgid uint32) string {
	if id, ok := r.cache[cgroupID]; ok {
		return id
	}

	id := classifyCgroupPath(cgroupPathForPID(tgid))
	if id == "unknown" {
		return id // don't cache a resolution failure; retry next time
	}

	if len(r.cache) >= maxIdentityCacheEntries {
		// Crude spike-grade eviction, same pattern as the lineage map in
		// main.go: drop one arbitrary entry rather than grow unbounded.
		for k := range r.cache {
			delete(r.cache, k)
			break
		}
	}
	r.cache[cgroupID] = id
	return id
}

// cgroupPathForPID reads the cgroup v2 unified-hierarchy path for tgid from
// /proc. Returns "" if the process has already exited or the line is
// missing (e.g. a mixed v1/v2 hierarchy without a unified "0::" entry).
func cgroupPathForPID(tgid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", tgid))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "0::"); ok {
			return rest
		}
	}
	return ""
}

// classifyCgroupPath maps a cgroupfs path to a fleet identity per
// architecture-specification.md §5.1/§5.2.
func classifyCgroupPath(path string) string {
	if path == "" {
		return "unknown"
	}

	// Reserved classes first (M1.5): collapse to one instance-agnostic
	// identity regardless of session number or which host it's on. Egress
	// from these stays visible in the event stream; a downstream review
	// queue (M2) is what actually excludes them by default.
	if sessionScopeRE.MatchString(path) {
		return "systemd:session"
	}
	if strings.HasSuffix(path, "crond.service") {
		return "systemd:crond.service"
	}

	if m := podmanScopeRE.FindStringSubmatch(path); m != nil {
		return "podman:" + podmanImageName(m[1])
	}

	if m := systemdServiceRE.FindStringSubmatch(path); m != nil {
		return "systemd:" + m[1]
	}

	return "unresolved:" + path
}

// podmanImageName shells out to `podman inspect` for the container's
// image:tag. Spike-grade: a CLI call per net-new container (cached
// thereafter via identityResolver), not the podman API socket. containerID
// may be a short or full hex ID; podman accepts either.
func podmanImageName(containerID string) string {
	out, err := exec.Command("podman", "inspect", "--format", "{{.ImageName}}", containerID).Output()
	if err != nil {
		return containerID // fallback: at least identify by container ID
	}
	name := strings.TrimSpace(string(out))
	if name == "" {
		return containerID
	}
	return name
}
