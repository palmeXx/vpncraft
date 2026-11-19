//go:build !windows

package relay

import (
	"fmt"
	"net"
	"net/netip"

	"golang.org/x/net/ipv4"
)

// xnetRawConn uses x/net/ipv4, which handles per-OS header quirks (e.g.
// host byte order of length fields on Darwin).
type xnetRawConn struct {
	conn *ipv4.RawConn
}

var _ rawConn = (*xnetRawConn)(nil)

func openRawConn() (rawConn, error) {
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
	return &xnetRawConn{conn: rc}, nil
}

func (c *xnetRawConn) send(src, dst netip.Addr, udp []byte) error {
	h := &ipv4.Header{
		Version:  ipv4.Version,
		Len:      ipv4HeaderLen,
		TotalLen: ipv4HeaderLen + len(udp),
		TTL:      defaultTTL,
		Protocol: protoUDP,
		Src:      src.AsSlice(),
		Dst:      dst.AsSlice(),
	}
	return c.conn.WriteTo(h, udp, nil)
}

func (c *xnetRawConn) Close() error { return c.conn.Close() }
