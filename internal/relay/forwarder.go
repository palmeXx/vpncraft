package relay

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"golang.org/x/net/ipv4"
)

const (
	ipv4HeaderLen = 20
	udpHeaderLen  = 8
	protoUDP      = 17
	defaultTTL    = 64
)

// RawForwarder sends UDP datagrams with a fixed source port through a raw
// IPv4 socket (IP_HDRINCL). Unlike a bound UDP socket it does not compete with
// a local application for that port, while replies still reach it.
type RawForwarder struct {
	conn    *ipv4.RawConn
	srcPort uint16

	mu   sync.Mutex
	srcs map[netip.Addr]netip.Addr // destination -> route source address
}

// NewRawForwarder opens a send-only raw socket (root/Administrator required).
func NewRawForwarder(srcPort uint16) (*RawForwarder, error) {
	// IPPROTO_RAW: the kernel never delivers inbound packets to this socket.
	pc, err := net.ListenPacket("ip4:255", "0.0.0.0")
	if err != nil {
		return nil, fmt.Errorf("open raw IPv4 socket: %w", err)
	}
	rc, err := ipv4.NewRawConn(pc)
	if err != nil {
		_ = pc.Close()
		return nil, fmt.Errorf("enable IP_HDRINCL: %w", err)
	}
	return &RawForwarder{conn: rc, srcPort: srcPort, srcs: make(map[netip.Addr]netip.Addr)}, nil
}

// Forward sends payload to dst, using the kernel-selected route source address.
func (f *RawForwarder) Forward(payload []byte, dst netip.AddrPort) error {
	src, err := f.sourceFor(dst)
	if err != nil {
		return err
	}
	udp := BuildUDP(netip.AddrPortFrom(src, f.srcPort), dst, payload)
	h := &ipv4.Header{
		Version:  ipv4.Version,
		Len:      ipv4HeaderLen,
		TotalLen: ipv4HeaderLen + len(udp),
		TTL:      defaultTTL,
		Protocol: protoUDP,
		Src:      src.AsSlice(),
		Dst:      dst.Addr().AsSlice(),
	}
	if err := f.conn.WriteTo(h, udp, nil); err != nil {
		return fmt.Errorf("send to %s: %w", dst, err)
	}
	return nil
}

// Close releases the raw socket.
func (f *RawForwarder) Close() error { return f.conn.Close() }

// sourceFor resolves (and caches) the local address the OS would use to reach dst.
// Connecting a UDP socket performs the route lookup without sending anything.
func (f *RawForwarder) sourceFor(dst netip.AddrPort) (netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if src, ok := f.srcs[dst.Addr()]; ok {
		return src, nil
	}
	c, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(dst))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("route lookup for %s: %w", dst.Addr(), err)
	}
	defer func() { _ = c.Close() }()
	la, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok {
		return netip.Addr{}, errors.New("route lookup: unexpected local address type")
	}
	src := la.AddrPort().Addr().Unmap()
	f.srcs[dst.Addr()] = src
	return src, nil
}

// BuildUDP returns a UDP header plus payload with a valid IPv4 pseudo-header checksum.
func BuildUDP(src, dst netip.AddrPort, payload []byte) []byte {
	length := udpHeaderLen + len(payload)
	b := make([]byte, length)
	binary.BigEndian.PutUint16(b[0:2], src.Port())
	binary.BigEndian.PutUint16(b[2:4], dst.Port())
	binary.BigEndian.PutUint16(b[4:6], uint16(length)) //nolint:gosec // bounded by MTU-sized captures
	copy(b[udpHeaderLen:], payload)

	s, d := src.Addr().As4(), dst.Addr().As4()
	var pseudo [12]byte
	copy(pseudo[0:4], s[:])
	copy(pseudo[4:8], d[:])
	pseudo[9] = protoUDP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(length)) //nolint:gosec // see above

	sum := checksum(checksum(0, pseudo[:]), b)
	csum := ^fold(sum)
	if csum == 0 {
		csum = 0xffff // RFC 768: transmitted all-ones when computed checksum is zero
	}
	binary.BigEndian.PutUint16(b[6:8], csum)
	return b
}

// checksum accumulates the RFC 1071 one's complement sum of b onto sum.
func checksum(sum uint32, b []byte) uint32 {
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	return sum
}

func fold(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return uint16(sum)
}
