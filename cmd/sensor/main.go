// Command sensor is the node-agent daemon (M1.1): it attaches eBPF programs
// and tracepoints, then prints one JSON line per observed event to stdout:
//
//	conn        net-new (cgroup, endpoint) egress tuple (deduped in-kernel)
//	exec        process exec lineage (joined onto conn events when known)
//	raw_socket  SOCK_RAW / AF_PACKET creation (invariant signal)
//
// Advisory-only: the eBPF programs never block.
//
// Configuration is a JSON file (packaging/sensor.json.example), reloaded on
// SIGHUP — log level takes effect immediately; a changed cgroup_path
// requires a full restart. Loads BPF programs directly (no bpfman broker;
// see docs/backlog.md's parking lot), so the daemon itself needs CAP_BPF.
//
// Build with `make build` at the repo root (runs go generate first; the
// generated bpf_bpf*.go files are gitignored). Install as a systemd service
// with `make install` (see packaging/specdev-sensor.service).
package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -type conn_event -type exec_event -type rawsock_event bpf ../../bpf/probes.c

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// Under connection churn, printing one line per event via unbuffered
// fmt.Println costs one write(2) syscall per event — a real, measured
// confound in the M0.6 benchmark (docs/report-m0.md) that had nothing to do
// with the eBPF/ringbuf path itself. Buffer stdout and flush on a bound
// (event count OR elapsed time, whichever comes first) so bursts amortize
// the syscall cost while sparse/idle periods still surface within the
// architecture's signal-latency budget (backlog.md: <10s).
const (
	flushEveryEvents = 50
	flushInterval    = 200 * time.Millisecond
)

// Wire constants mirrored from bpf/common.h. bpf2go does not propagate
// #defines/enums into the generated Go, so these are synced by hand: if you
// change a value in common.h, change it here. A mismatch silently misparses
// events instead of failing to build.
const (
	familyV4 = 4  // FAMILY_V4
	familyV6 = 6  // FAMILY_V6
	protoTCP = 6  // PROTO_TCP
	protoUDP = 17 // PROTO_UDP
)

// Event type tags — mirror of enum event_type in bpf/common.h.
const (
	eventConn    = 1 // EVENT_CONN
	eventExec    = 2 // EVENT_EXEC
	eventRawSock = 3 // EVENT_RAW_SOCK
)

// Output schemas. M1 replaces stdout with mTLS upload; keep these stable
// until then.

type connOut struct {
	Type          string `json:"type"` // "conn"
	Instance      string `json:"instance"`
	CgroupID      uint64 `json:"cgroup_id"`
	FleetIdentity string `json:"fleet_identity"`
	Addr          string `json:"addr"`
	FQDN          string `json:"fqdn,omitempty"`
	Port          uint16 `json:"port"`
	Protocol      string `json:"protocol"`
	Family        string `json:"family"`
	PID           uint32 `json:"pid"`
	Comm          string `json:"comm"`
	ExecPath      string `json:"exec_path,omitempty"`
	ParentComm    string `json:"parent_comm,omitempty"`
	TsNs          uint64 `json:"ts_ns"`
}

type execOut struct {
	Type          string `json:"type"` // "exec"
	Instance      string `json:"instance"`
	CgroupID      uint64 `json:"cgroup_id"`
	FleetIdentity string `json:"fleet_identity"`
	PID           uint32 `json:"pid"`
	Comm          string `json:"comm"`
	Path          string `json:"path"`
	PPID          uint32 `json:"ppid,omitempty"`
	ParentComm    string `json:"parent_comm,omitempty"`
	TsNs          uint64 `json:"ts_ns"`
}

type rawSockOut struct {
	Type          string `json:"type"`   // "raw_socket"
	Signal        string `json:"signal"` // "raw_socket_creation"
	Instance      string `json:"instance"`
	CgroupID      uint64 `json:"cgroup_id"`
	FleetIdentity string `json:"fleet_identity"`
	PID           uint32 `json:"pid"`
	Comm          string `json:"comm"`
	Family        int32  `json:"family"`
	SockType      int32  `json:"sock_type"`
	Protocol      int32  `json:"protocol"`
	TsNs          uint64 `json:"ts_ns"`
}

// lineageKey joins exec and conn events. Note the spike-grade caveats in the
// README: pid reuse can mis-attribute on busy hosts, and lineage only covers
// execs observed after sensor start (eager in-kernel resolution is M1).
type lineageKey struct {
	cgroupID uint64
	tgid     uint32
}

type lineageEntry struct {
	path       string
	ppid       uint32
	parentComm string
}

const maxLineageEntries = 65536

// errThrottle rate-limits repeated error logs: a systematic ABI mismatch must
// not spin-log once per ring-buffer record. First 5 occurrences log
// immediately, then every 1000th.
type errThrottle struct{ n uint64 }

func (t *errThrottle) log(msg string, args ...any) {
	t.n++
	if t.n <= 5 || t.n%1000 == 0 {
		slog.Warn(msg, append(args, "occurrence", t.n)...)
	}
}

func cstr(b []byte) string {
	return string(bytes.TrimRight(b, "\x00"))
}

func main() {
	configPath := flag.String("config", "/etc/specification-deviation/sensor.json",
		"path to daemon config file (a missing file falls back to defaults)")
	cgroupOverride := flag.String("cgroup", "",
		"cgroup v2 path override for the egress hooks (defaults to the config file's cgroup_path, or /sys/fs/cgroup if unset)")
	flag.Parse()

	programLevel := new(slog.LevelVar)
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: programLevel})))

	cfg, err := loadConfig(*configPath)
	if err != nil {
		slog.Error("failed to load config", "path", *configPath, "error", err)
		os.Exit(1)
	}
	programLevel.Set(parseLogLevel(cfg.LogLevel))
	if *cgroupOverride != "" {
		cfg.CgroupPath = *cgroupOverride
	}

	if cfg.CgroupPath == "/sys/fs/cgroup" {
		slog.Warn("attaching to the root cgroup — ALL node egress will be observed",
			"hint", "for an isolated test use: systemd-run --scope --unit=egress-test bash")
	}

	if err := run(cfg, *configPath, programLevel); err != nil {
		slog.Error("sensor exited with error", "error", err)
		os.Exit(1)
	}
}

func run(cfg Config, configPath string, level *slog.LevelVar) error {
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		return fmt.Errorf("loading eBPF objects (needs root/CAP_BPF, cgroup v2, BTF): %w", err)
	}
	defer objs.Close()

	links, err := attachAll(cfg.CgroupPath, &objs)
	if err != nil {
		return err
	}
	defer func() {
		for _, l := range links {
			l.Close()
		}
	}()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return fmt.Errorf("ringbuf reader: %w", err)
	}
	defer rd.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		rd.Close()
	}()

	// SIGHUP reload (systemd `ExecReload=`): log level applies immediately;
	// a changed cgroup_path needs a full restart to re-attach, since that
	// means tearing down and recreating the cgroup links above.
	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-sighup:
				newCfg, err := loadConfig(configPath)
				if err != nil {
					slog.Error("reload failed, keeping current settings", "path", configPath, "error", err)
					continue
				}
				level.Set(parseLogLevel(newCfg.LogLevel))
				slog.Info("config reloaded", "log_level", newCfg.LogLevel)
				if newCfg.CgroupPath != cfg.CgroupPath {
					slog.Warn("cgroup_path changed but requires a full restart to take effect",
						"current", cfg.CgroupPath, "new", newCfg.CgroupPath)
				}
			}
		}
	}()

	dns := newDNSCache()
	go snoopDNS(ctx.Done(), dns)

	var up *uploader
	if cfg.CentralURL != "" {
		up = newUploader(cfg.CentralURL)
		go up.run(ctx)
		slog.Info("central upload enabled", "url", cfg.CentralURL)
	}

	slog.Info("sensor running; events on stdout as JSON lines", "cgroup_path", cfg.CgroupPath)

	out := bufio.NewWriterSize(os.Stdout, 64*1024)
	unflushed := 0
	lastFlush := time.Now()
	maybeFlush := func() {
		unflushed++
		if unflushed >= flushEveryEvents || time.Since(lastFlush) >= flushInterval {
			out.Flush()
			unflushed = 0
			lastFlush = time.Now()
		}
	}

	lineage := make(map[lineageKey]lineageEntry)
	ident := newIdentityResolver()
	selfPID := uint32(os.Getpid())
	instance, err := os.Hostname()
	if err != nil {
		slog.Warn("hostname lookup failed, tagging events as \"unknown\"", "error", err)
		instance = "unknown"
	}
	var decodeErrs errThrottle
	var counts [4]uint64 // indexed by event type tag; [0] = unknown

	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				break
			}
			return fmt.Errorf("read ringbuf: %w", err)
		}

		if len(rec.RawSample) < 8 {
			decodeErrs.log("short record — possible ABI mismatch with bpf/common.h", "bytes", len(rec.RawSample))
			continue
		}

		switch typ := binary.LittleEndian.Uint64(rec.RawSample[:8]); typ {
		case eventConn:
			var ev bpfConnEvent
			if err := binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, &ev); err != nil {
				decodeErrs.log("decode conn event failed — possible ABI mismatch with bpf/common.h", "error", err)
				continue
			}
			emit(out, up, connEvent(&ev, lineage, ident, dns, instance))
			maybeFlush()
			counts[eventConn]++
		case eventExec:
			var ev bpfExecEvent
			if err := binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, &ev); err != nil {
				decodeErrs.log("decode exec event failed — possible ABI mismatch with bpf/common.h", "error", err)
				continue
			}
			emit(out, up, execEvent(&ev, lineage, ident, instance))
			maybeFlush()
			counts[eventExec]++
		case eventRawSock:
			var ev bpfRawsockEvent
			if err := binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, &ev); err != nil {
				decodeErrs.log("decode rawsock event failed — possible ABI mismatch with bpf/common.h", "error", err)
				continue
			}
			if ev.Tgid == selfPID {
				continue // our own DNS snooper's AF_PACKET socket -- expected, not a signal
			}
			emit(out, up, rawSockEvent(&ev, ident, instance))
			maybeFlush()
			counts[eventRawSock]++
		default:
			decodeErrs.log("unknown event type — possible ABI mismatch with bpf/common.h", "type", typ)
			counts[0]++
		}
	}
	out.Flush()

	if up != nil {
		// ctx is already done (that's why the read loop above exited), so a
		// last drain needs its own context -- otherwise this would return
		// immediately without sending. A graceful shutdown should not lose
		// whatever's still buffered any more than a central outage does.
		drainCtx, cancel := context.WithTimeout(context.Background(), uploadTimeout)
		up.drain(drainCtx)
		cancel()
	}

	slog.Info("sensor stopped",
		"conn", counts[eventConn], "exec", counts[eventExec], "raw_socket", counts[eventRawSock],
		"unknown", counts[0], "decode_errors", decodeErrs.n)
	return nil
}

func attachAll(cgroupPath string, objs *bpfObjects) ([]link.Link, error) {
	var links []link.Link

	fail := func(err error) ([]link.Link, error) {
		for _, l := range links {
			l.Close()
		}
		return nil, err
	}

	cgroupHooks := []struct {
		attach ebpf.AttachType
		prog   *ebpf.Program
	}{
		{ebpf.AttachCGroupInet4Connect, objs.EgressConnect4},
		{ebpf.AttachCGroupInet6Connect, objs.EgressConnect6},
		{ebpf.AttachCGroupUDP4Sendmsg, objs.EgressSendmsg4},
		{ebpf.AttachCGroupUDP6Sendmsg, objs.EgressSendmsg6},
	}
	for _, h := range cgroupHooks {
		l, err := link.AttachCgroup(link.CgroupOptions{
			Path:    cgroupPath,
			Attach:  h.attach,
			Program: h.prog,
		})
		if err != nil {
			return fail(fmt.Errorf("attach %v to %s: %w", h.attach, cgroupPath, err))
		}
		links = append(links, l)
	}

	tracepoints := []struct {
		group, name string
		prog        *ebpf.Program
	}{
		{"sched", "sched_process_exec", objs.HandleExec},
		{"syscalls", "sys_enter_socket", objs.HandleRawSocket},
	}
	for _, tp := range tracepoints {
		l, err := link.Tracepoint(tp.group, tp.name, tp.prog, nil)
		if err != nil {
			return fail(fmt.Errorf("attach tracepoint %s/%s: %w", tp.group, tp.name, err))
		}
		links = append(links, l)
	}

	return links, nil
}

// connEvent converts a kernel conn event to JSON output, enriched with exec
// lineage when the table has an entry for this (cgroup, process).
func connEvent(ev *bpfConnEvent, lineage map[lineageKey]lineageEntry, ident *identityResolver, dns *dnsCache, instance string) connOut {
	out := connOut{
		Type:          "conn",
		Instance:      instance,
		CgroupID:      ev.Key.CgroupId,
		FleetIdentity: ident.resolve(ev.Key.CgroupId, ev.Tgid),
		Port:          ev.Key.Dport,
		PID:           ev.Tgid,
		Comm:          cstr(ev.Comm[:]),
		TsNs:          ev.Ts,
	}

	var addr netip.Addr
	switch ev.Key.Family {
	case familyV4:
		out.Family = "ipv4"
		addr = netip.AddrFrom4([4]byte(ev.Key.Addr[:4]))
	case familyV6:
		out.Family = "ipv6"
		addr = netip.AddrFrom16(ev.Key.Addr)
	default:
		out.Family = fmt.Sprintf("family:%d", ev.Key.Family)
	}
	if addr.IsValid() {
		out.Addr = addr.String()
		if fqdn, ok := dns.lookup(addr); ok {
			out.FQDN = fqdn
		}
	}

	switch ev.Key.Protocol {
	case protoTCP:
		out.Protocol = "tcp"
	case protoUDP:
		out.Protocol = "udp"
	default:
		out.Protocol = fmt.Sprintf("proto:%d", ev.Key.Protocol)
	}

	if e, ok := lineage[lineageKey{ev.Key.CgroupId, ev.Tgid}]; ok {
		out.ExecPath = e.path
		out.ParentComm = e.parentComm
	}

	return out
}

// execEvent records lineage for later conn events and converts to JSON output.
// Parent info is best-effort from /proc: a short-lived process may already be
// gone, in which case the fields are simply omitted.
func execEvent(ev *bpfExecEvent, lineage map[lineageKey]lineageEntry, ident *identityResolver, instance string) execOut {
	path := cstr(ev.Path[:])
	ppid, parentComm := parentFromProc(ev.Tgid)

	if len(lineage) >= maxLineageEntries {
		// Crude spike-grade eviction: drop one arbitrary entry. Proper
		// lifecycle (expiry by cgroup lifetime) is M1.
		for k := range lineage {
			delete(lineage, k)
			break
		}
	}
	lineage[lineageKey{ev.CgroupId, ev.Tgid}] = lineageEntry{
		path:       path,
		ppid:       ppid,
		parentComm: parentComm,
	}

	return execOut{
		Type:          "exec",
		Instance:      instance,
		CgroupID:      ev.CgroupId,
		FleetIdentity: ident.resolve(ev.CgroupId, ev.Tgid),
		PID:           ev.Tgid,
		Comm:          cstr(ev.Comm[:]),
		Path:          path,
		PPID:          ppid,
		ParentComm:    parentComm,
		TsNs:          ev.Ts,
	}
}

func rawSockEvent(ev *bpfRawsockEvent, ident *identityResolver, instance string) rawSockOut {
	return rawSockOut{
		Type:          "raw_socket",
		Signal:        "raw_socket_creation",
		Instance:      instance,
		CgroupID:      ev.CgroupId,
		FleetIdentity: ident.resolve(ev.CgroupId, ev.Tgid),
		PID:           ev.Tgid,
		Comm:          cstr(ev.Comm[:]),
		Family:        ev.Family,
		SockType:      ev.SockType,
		Protocol:      ev.Protocol,
		TsNs:          ev.Ts,
	}
}

// parentFromProc best-effort reads a process's ppid and parent comm from
// /proc. Returns zero values if the process already exited.
func parentFromProc(pid uint32) (uint32, string) {
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, ""
	}

	var ppid uint32
	for line := range strings.Lines(string(status)) {
		if rest, ok := strings.CutPrefix(line, "PPid:"); ok {
			if _, err := fmt.Sscanf(rest, "%d", &ppid); err != nil {
				return 0, ""
			}
			break
		}
	}
	if ppid == 0 {
		return 0, ""
	}

	comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", ppid))
	if err != nil {
		return ppid, ""
	}
	return ppid, strings.TrimSpace(string(comm))
}

func emit(w *bufio.Writer, up *uploader, v any) {
	line, err := json.Marshal(v)
	if err != nil {
		slog.Error("marshal event failed", "error", err)
		return
	}
	w.Write(line)
	w.WriteByte('\n')
	if up != nil {
		up.enqueue(line)
	}
}
