package relay

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"
)

// TestOpenRawConn exercises the platform raw socket. Unprivileged, the error
// must map to os.ErrPermission (drives the "run with sudo/Administrator"
// hint). Privileged, a real datagram must arrive with the fixed source port,
// which catches runtime stubs that compile fine (e.g. x/net's sendmsg on
// Windows). Runs privileged via `make test-integration-privileged` and on the
// Windows CI runner.
func TestOpenRawConn(t *testing.T) {
	conn, err := openRawConn()
	if err != nil {
		if !errors.Is(err, os.ErrPermission) {
			t.Fatalf("openRawConn() error = %v, want os.ErrPermission when unprivileged", err)
		}
		t.Skip("no raw socket privileges: permission mapping verified, send path skipped")
	}
	t.Cleanup(func() { _ = conn.Close() })

	ln, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	lo := netip.MustParseAddr("127.0.0.1")
	dst := ln.LocalAddr().(*net.UDPAddr).AddrPort()
	payload := []byte{0xF7, 0x2F, 0x04, 0x00}
	if err := conn.send(lo, lo, BuildUDP(netip.AddrPortFrom(lo, 6112), dst, payload)); err != nil {
		t.Fatalf("send() error = %v", err)
	}

	if err := ln.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, from, err := ln.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatalf("datagram not received: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) || from.Port() != 6112 {
		t.Errorf("received % x from %s, want % x from port 6112", buf[:n], from, payload)
	}
}
