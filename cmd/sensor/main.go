// Command sensor is the M0 observation spike: it attaches eBPF programs and
// tracepoints, then prints one JSON line per observed event:
//
//	conn        net-new (cgroup, endpoint) egress tuple (deduped in-kernel)
//	exec        process exec lineage (joined onto conn events when known)
//	raw_socket  SOCK_RAW / AF_PACKET creation (invariant signal)
//
// Advisory-only: the eBPF programs never block.
//
// Build with `make build` at the repo root (runs go generate first; the
// generated bpf_bpf*.go files are gitignored).
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
	"log"
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
	Type       string `json:"type"` // "conn"
	CgroupID   uint64 `json:"cgroup_id"`
	Addr       string `json:"addr"`
	Port       uint16 `json:"port"`
	Protocol   string `json:"protocol"`
	Family     string `json:"family"`
	PID        uint32 `json:"pid"`
	Comm       string `json:"comm"`
	ExecPath   string `json:"exec_path,omitempty"`
	ParentComm string `json:"parent_comm,omitempty"`
	TsNs       uint64 `json:"ts_ns"`
}

type execOut struct {
	Type       string `json:"type"` // "exec"
	CgroupID   uint64 `json:"cgroup_id"`
	PID        uint32 `json:"pid"`
	Comm       string `json:"comm"`
	Path       string `json:"path"`
	PPID       uint32 `json:"ppid,omitempty"`
	ParentComm string `json:"parent_comm,omitempty"`
	TsNs       uint64 `json:"ts_ns"`
}

type rawSockOut struct {
	Type     string `json:"type"`   // "raw_socket"
	Signal   string `json:"signal"` // "raw_socket_creation"
	CgroupID uint64 `json:"cgroup_id"`
	PID      uint32 `json:"pid"`
	Comm     string `json:"comm"`
	Family   int32  `json:"family"`
	SockType int32  `json:"sock_type"`
	Protocol int32  `json:"protocol"`
	TsNs     uint64 `json:"ts_ns"`
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

func (t *errThrottle) logf(format string, args ...any) {
	t.n++
	if t.n <= 5 || t.n%1000 == 0 {
		log.Printf(format+" (occurrence %d)", append(args, t.n)...)
	}
}

func cstr(b []byte) string {
	return string(bytes.TrimRight(b, "\x00"))
}

func main() {
	cgroupPath := flag.String("cgroup", "/sys/fs/cgroup",
		"cgroup v2 path for the egress hooks (the root observes the whole node; tracepoint probes are always host-wide)")
	flag.Parse()

	if *cgroupPath == "/sys/fs/cgroup" {
		fmt.Fprintln(os.Stderr, "warning: attaching to the root cgroup — ALL node egress will be observed.")
		fmt.Fprintln(os.Stderr, "for an isolated test use: systemd-run --scope --unit=egress-test bash")
	}

	if err := run(*cgroupPath); err != nil {
		log.Fatal(err)
	}
}

func run(cgroupPath string) error {
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		return fmt.Errorf("loading eBPF objects (needs root/CAP_BPF, cgroup v2, BTF): %w", err)
	}
	defer objs.Close()

	links, err := attachAll(cgroupPath, &objs)
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

	fmt.Fprintln(os.Stderr, "sensor running; events on stdout as JSON lines")

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
			decodeErrs.logf("short record (%d bytes) — possible ABI mismatch with bpf/common.h", len(rec.RawSample))
			continue
		}

		switch typ := binary.LittleEndian.Uint64(rec.RawSample[:8]); typ {
		case eventConn:
			var ev bpfConnEvent
			if err := binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, &ev); err != nil {
				decodeErrs.logf("decode conn event: %v — possible ABI mismatch with bpf/common.h", err)
				continue
			}
			emit(out, connEvent(&ev, lineage))
			maybeFlush()
			counts[eventConn]++
		case eventExec:
			var ev bpfExecEvent
			if err := binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, &ev); err != nil {
				decodeErrs.logf("decode exec event: %v — possible ABI mismatch with bpf/common.h", err)
				continue
			}
			emit(out, execEvent(&ev, lineage))
			maybeFlush()
			counts[eventExec]++
		case eventRawSock:
			var ev bpfRawsockEvent
			if err := binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, &ev); err != nil {
				decodeErrs.logf("decode rawsock event: %v — possible ABI mismatch with bpf/common.h", err)
				continue
			}
			emit(out, rawSockEvent(&ev))
			maybeFlush()
			counts[eventRawSock]++
		default:
			decodeErrs.logf("unknown event type %d — possible ABI mismatch with bpf/common.h", typ)
			counts[0]++
		}
	}
	out.Flush()

	fmt.Fprintf(os.Stderr, "sensor stopped; conn=%d exec=%d raw_socket=%d unknown=%d decode_errors=%d\n",
		counts[eventConn], counts[eventExec], counts[eventRawSock], counts[0], decodeErrs.n)
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
func connEvent(ev *bpfConnEvent, lineage map[lineageKey]lineageEntry) connOut {
	out := connOut{
		Type:     "conn",
		CgroupID: ev.Key.CgroupId,
		Port:     ev.Key.Dport,
		PID:      ev.Tgid,
		Comm:     cstr(ev.Comm[:]),
		TsNs:     ev.Ts,
	}

	switch ev.Key.Family {
	case familyV4:
		out.Family = "ipv4"
		out.Addr = netip.AddrFrom4([4]byte(ev.Key.Addr[:4])).String()
	case familyV6:
		out.Family = "ipv6"
		out.Addr = netip.AddrFrom16(ev.Key.Addr).String()
	default:
		out.Family = fmt.Sprintf("family:%d", ev.Key.Family)
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
func execEvent(ev *bpfExecEvent, lineage map[lineageKey]lineageEntry) execOut {
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
		Type:       "exec",
		CgroupID:   ev.CgroupId,
		PID:        ev.Tgid,
		Comm:       cstr(ev.Comm[:]),
		Path:       path,
		PPID:       ppid,
		ParentComm: parentComm,
		TsNs:       ev.Ts,
	}
}

func rawSockEvent(ev *bpfRawsockEvent) rawSockOut {
	return rawSockOut{
		Type:     "raw_socket",
		Signal:   "raw_socket_creation",
		CgroupID: ev.CgroupId,
		PID:      ev.Tgid,
		Comm:     cstr(ev.Comm[:]),
		Family:   ev.Family,
		SockType: ev.SockType,
		Protocol: ev.Protocol,
		TsNs:     ev.Ts,
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

func emit(w *bufio.Writer, v any) {
	line, err := json.Marshal(v)
	if err != nil {
		log.Printf("marshal event: %v", err)
		return
	}
	w.Write(line)
	w.WriteByte('\n')
}
