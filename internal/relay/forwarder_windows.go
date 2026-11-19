//go:build windows

package relay

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sync/atomic"

	"golang.org/x/sys/windows"
)

// ipprotoRaw is IPPROTO_RAW, not exported by x/sys/windows.
const ipprotoRaw = 255

// winRawConn sends complete IPv4 packets via sendto on a raw socket with
// IP_HDRINCL. x/net/ipv4.RawConn cannot be used: it relies on sendmsg, which
// x/net does not implement on Windows.
type winRawConn struct {
	fd windows.Handle
	id atomic.Uint32 // IPv4 identification, incremented per packet
}

var _ rawConn = (*winRawConn)(nil)

func openRawConn() (rawConn, error) {
	fd, err := windows.Socket(windows.AF_INET, windows.SOCK_RAW, ipprotoRaw)
	if err != nil {
		if errors.Is(err, windows.WSAEACCES) {
			return nil, fmt.Errorf("open raw IPv4 socket: %w", os.ErrPermission)
		}
		return nil, fmt.Errorf("open raw IPv4 socket: %w", err)
	}
	if err := windows.SetsockoptInt(fd, windows.IPPROTO_IP, windows.IP_HDRINCL, 1); err != nil {
		_ = windows.Closesocket(fd)
		return nil, fmt.Errorf("enable IP_HDRINCL: %w", err)
	}
	return &winRawConn{fd: fd}, nil
}

func (c *winRawConn) send(src, dst netip.Addr, udp []byte) error {
	pkt := BuildIPv4(src, dst, uint16(c.id.Add(1)), udp) //nolint:gosec // identification wraps around by design
	return windows.Sendto(c.fd, pkt, 0, &windows.SockaddrInet4{Addr: dst.As4()})
}

func (c *winRawConn) Close() error { return windows.Closesocket(c.fd) }
