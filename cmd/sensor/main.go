// Command sensor is the M0 egress-observation spike: it attaches eBPF
// programs to a cgroup v2 hierarchy and prints one JSON line per net-new
// (cgroup, endpoint) tuple observed. Advisory-only: the eBPF programs always
// allow the connection.
//
// Build with `make build` at the repo root (runs go generate first; the
// generated bpf_bpf*.go files are gitignored).
package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -type conn_event bpf ../../bpf/egress.c

import (
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
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// eventOut is the M0 wire format: one JSON line per net-new tuple.
// M1 replaces stdout with mTLS upload; keep this schema stable until then.
type eventOut struct {
	CgroupID uint64 `json:"cgroup_id"`
	Addr     string `json:"addr"`
	Port     uint16 `json:"port"`
	Protocol string `json:"protocol"`
	Family   string `json:"family"`
	PID      uint32 `json:"pid"`
	Comm     string `json:"comm"`
	TsNs     uint64 `json:"ts_ns"`
}

func main() {
	cgroupPath := flag.String("cgroup", "/sys/fs/cgroup",
		"cgroup v2 path to attach to (the root observes the whole node)")
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

	fmt.Fprintln(os.Stderr, "sensor running; net-new (cgroup, endpoint) tuples on stdout as JSON lines")

	var count uint64
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				break
			}
			return fmt.Errorf("read ringbuf: %w", err)
		}

		var ev bpfConnEvent
		if err := binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, &ev); err != nil {
			log.Printf("decode event: %v", err)
			continue
		}

		line, err := json.Marshal(toOut(&ev))
		if err != nil {
			log.Printf("marshal event: %v", err)
			continue
		}
		fmt.Println(string(line))
		count++
	}

	fmt.Fprintf(os.Stderr, "sensor stopped; %d events emitted\n", count)
	return nil
}

func attachAll(cgroupPath string, objs *bpfObjects) ([]link.Link, error) {
	specs := []struct {
		attach ebpf.AttachType
		prog   *ebpf.Program
	}{
		{ebpf.AttachCGroupInet4Connect, objs.EgressConnect4},
		{ebpf.AttachCGroupInet6Connect, objs.EgressConnect6},
		{ebpf.AttachCGroupUDP4Sendmsg, objs.EgressSendmsg4},
		{ebpf.AttachCGroupUDP6Sendmsg, objs.EgressSendmsg6},
	}

	var links []link.Link
	for _, s := range specs {
		l, err := link.AttachCgroup(link.CgroupOptions{
			Path:    cgroupPath,
			Attach:  s.attach,
			Program: s.prog,
		})
		if err != nil {
			for _, l := range links {
				l.Close()
			}
			return nil, fmt.Errorf("attach %v to %s: %w", s.attach, cgroupPath, err)
		}
		links = append(links, l)
	}
	return links, nil
}

func toOut(ev *bpfConnEvent) eventOut {
	out := eventOut{
		CgroupID: ev.Key.CgroupId,
		Port:     ev.Key.Dport,
		PID:      ev.Tgid,
		Comm:     string(bytes.TrimRight(ev.Comm[:], "\x00")),
		TsNs:     ev.Ts,
	}

	switch ev.Key.Family {
	case 4: // AF_IPV4
		out.Family = "ipv4"
		out.Addr = netip.AddrFrom4([4]byte(ev.Key.Addr[:4])).String()
	case 6: // AF_IPV6
		out.Family = "ipv6"
		out.Addr = netip.AddrFrom16(ev.Key.Addr).String()
	default:
		out.Family = fmt.Sprintf("family:%d", ev.Key.Family)
	}

	switch ev.Key.Protocol {
	case 6: // PROTO_TCP
		out.Protocol = "tcp"
	case 17: // PROTO_UDP
		out.Protocol = "udp"
	default:
		out.Protocol = fmt.Sprintf("proto:%d", ev.Key.Protocol)
	}

	return out
}
