// Passive DNS snooper (M1.2): observes OTHER processes' DNS responses to
// build an IP -> FQDN cache with TTL, so conn events can carry names
// instead of raw IPs ("names don't rot" -- architecture-specification.md
// §2.1).
//
// Genuine passive snooping of traffic not addressed to your own socket
// needs a packet-capture primitive -- there's no way around that. This uses
// AF_PACKET in SOCK_DGRAM ("cooked") mode, which strips the link-layer
// header for us, so parsing starts at the IP layer. IPv4 only for this
// milestone; IPv6 DNS snooping is a documented gap, the same style as the
// existing DoH-bypass caveat (architecture-specification.md §13). No
// classic-BPF filter is attached to the socket either -- everything on the
// interface is copied to userspace and cheaply rejected by inspecting a few
// header bytes before full DNS parsing. Both are fine for a PoC; both would
// need revisiting for anything beyond one.
//
// This is exactly the primitive M0.5's raw-socket invariant flags. The
// exemption lives in userspace (run() in main.go skips raw_socket events
// whose tgid is our own PID) rather than in the kernel program -- simpler,
// and an exact PID match is no less robust than a spoofable identity string
// would have been.
package main

import (
	"encoding/binary"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/unix"
)

const (
	maxDNSCacheEntries = 65536
	dnsRecvBufSize     = 4096
)

type dnsCacheEntry struct {
	fqdn      string
	expiresAt time.Time
}

// dnsCache is written by the snooper goroutine and read by the event-loop
// goroutine in run() -- unlike identityResolver, this genuinely needs
// locking.
type dnsCache struct {
	mu      sync.RWMutex
	entries map[netip.Addr]dnsCacheEntry
}

func newDNSCache() *dnsCache {
	return &dnsCache{entries: make(map[netip.Addr]dnsCacheEntry)}
}

func (c *dnsCache) lookup(addr netip.Addr) (string, bool) {
	c.mu.RLock()
	e, ok := c.entries[addr]
	c.mu.RUnlock()
	if !ok || time.Now().After(e.expiresAt) {
		return "", false
	}
	return e.fqdn, true
}

func (c *dnsCache) put(addr netip.Addr, fqdn string, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= maxDNSCacheEntries {
		// Same crude spike-grade eviction as the lineage and identity
		// caches in this package: drop one arbitrary entry rather than
		// grow unbounded.
		for k := range c.entries {
			delete(c.entries, k)
			break
		}
	}
	c.entries[addr] = dnsCacheEntry{fqdn: fqdn, expiresAt: time.Now().Add(ttl)}
}

// snoopDNS opens an AF_PACKET/SOCK_DGRAM socket and feeds parsed A records
// into cache until done is closed. A failure to open the socket is logged,
// not fatal -- the rest of the sensor works fine without DNS snooping, an
// endpoint just shows as a bare IP instead of an FQDN.
func snoopDNS(done <-chan struct{}, cache *dnsCache) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM, int(htons(unix.ETH_P_IP)))
	if err != nil {
		slog.Error("DNS snooper disabled: opening AF_PACKET socket failed", "error", err)
		return
	}
	defer unix.Close(fd)

	go func() {
		<-done
		unix.Close(fd)
	}()

	buf := make([]byte, dnsRecvBufSize)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			return // socket closed on shutdown, or a real error -- either way, stop
		}
		parseIPPacket(buf[:n], cache)
	}
}

// htons: AF_PACKET's socket() protocol argument is the on-wire EtherType,
// which the kernel compares in network byte order.
func htons(v uint16) uint16 {
	return (v<<8)&0xff00 | v>>8
}

// parseIPPacket expects buf to start at the IPv4 header (AF_PACKET
// SOCK_DGRAM already stripped the Ethernet header). Anything that isn't a
// well-formed UDP-from-port-53 packet is dropped immediately and silently
// -- this fires on the vast majority of traffic on the interface by design
// (see package doc), so it must not log.
func parseIPPacket(buf []byte, cache *dnsCache) {
	if len(buf) < 20 || buf[0]>>4 != 4 {
		return // not IPv4 (or truncated) -- IPv6 DNS snooping is out of scope for M1.2
	}
	ihl := int(buf[0]&0x0f) * 4
	if ihl < 20 || len(buf) < ihl+8 {
		return
	}
	if buf[9] != unix.IPPROTO_UDP {
		return
	}

	udp := buf[ihl:]
	if binary.BigEndian.Uint16(udp[0:2]) != 53 {
		return // only responses matter to a snooper -- source port 53
	}
	udpLen := int(binary.BigEndian.Uint16(udp[4:6]))
	if udpLen < 8 || len(udp) < udpLen {
		return
	}

	var msg dnsmessage.Message
	if err := msg.Unpack(udp[8:udpLen]); err != nil {
		return // not a well-formed DNS message -- silently ignore
	}

	for _, a := range msg.Answers {
		body, ok := a.Body.(*dnsmessage.AResource)
		if !ok {
			continue // AAAA and other record types: not handled this milestone
		}
		cache.put(netip.AddrFrom4(body.A), a.Header.Name.String(),
			time.Duration(a.Header.TTL)*time.Second)
	}
}
