package relay

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/palmeXx/vpncraft/internal/capture"
)

type sent struct {
	payload []byte
	dst     netip.AddrPort
}

type fakeForwarder struct {
	sent []sent
	fail map[netip.Addr]bool
}

func (f *fakeForwarder) Forward(payload []byte, dst netip.AddrPort) error {
	if f.fail[dst.Addr()] {
		return errors.New("network unreachable")
	}
	f.sent = append(f.sent, sent{payload: bytes.Clone(payload), dst: dst})
	return nil
}

func newTestRelay(fwd Forwarder, out *bytes.Buffer, peers ...string) *Relay {
	addrs := make([]netip.Addr, len(peers))
	for i, p := range peers {
		addrs[i] = netip.MustParseAddr(p)
	}
	r := New(addrs, 6112, fwd, out)
	r.now = func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) }
	return r
}

func packet(src, dst string, payload ...byte) capture.Packet {
	return capture.Packet{
		Src:     netip.MustParseAddrPort(src),
		Dst:     netip.MustParseAddrPort(dst),
		Payload: payload,
	}
}

func TestRelayForwardsToAllPeers(t *testing.T) {
	fwd := &fakeForwarder{}
	var out bytes.Buffer
	r := newTestRelay(fwd, &out, "100.64.0.2", "100.64.0.3")

	r.Handle(packet("192.168.1.10:6112", "255.255.255.255:6112", 0xF7, 0x31, 0x10, 0x00))

	if len(fwd.sent) != 2 {
		t.Fatalf("forwarded %d packets, want 2", len(fwd.sent))
	}
	for i, want := range []string{"100.64.0.2:6112", "100.64.0.3:6112"} {
		if fwd.sent[i].dst.String() != want {
			t.Errorf("sent[%d].dst = %s, want %s", i, fwd.sent[i].dst, want)
		}
		if !bytes.Equal(fwd.sent[i].payload, []byte{0xF7, 0x31, 0x10, 0x00}) {
			t.Errorf("sent[%d].payload = %x", i, fwd.sent[i].payload)
		}
	}
	wantOut := "[2026-01-02 03:04:05] [+] Caught local WC3 broadcast from 192.168.1.10 -> 255.255.255.255\n" +
		"    └─> Forwarded to 100.64.0.2:6112\n" +
		"    └─> Forwarded to 100.64.0.3:6112\n"
	if out.String() != wantOut {
		t.Errorf("output =\n%s\nwant\n%s", out.String(), wantOut)
	}
}

func TestRelaySkips(t *testing.T) {
	tests := []struct {
		name string
		pkt  capture.Packet
	}{
		{"from peer", packet("100.64.0.2:6112", "255.255.255.255:6112", 0xF7, 0x31)},
		{"to peer (own relayed packet)", packet("100.64.0.1:6112", "100.64.0.2:6112", 0xF7, 0x31)},
		{"non w3gs", packet("192.168.1.10:6112", "255.255.255.255:6112", 0x01, 0x31)},
		{"empty payload", packet("192.168.1.10:6112", "255.255.255.255:6112")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fwd := &fakeForwarder{}
			var out bytes.Buffer
			newTestRelay(fwd, &out, "100.64.0.2").Handle(tt.pkt)
			if len(fwd.sent) != 0 || out.Len() != 0 {
				t.Errorf("forwarded %d packets, output %q; want none", len(fwd.sent), out.String())
			}
		})
	}
}

func TestRelayReportsForwardErrors(t *testing.T) {
	fwd := &fakeForwarder{fail: map[netip.Addr]bool{netip.MustParseAddr("100.64.0.2"): true}}
	var out bytes.Buffer
	r := newTestRelay(fwd, &out, "100.64.0.2", "100.64.0.3")

	r.Handle(packet("192.168.1.10:6112", "255.255.255.255:6112", 0xF7, 0x2F))

	if len(fwd.sent) != 1 || fwd.sent[0].dst.Addr().String() != "100.64.0.3" {
		t.Fatalf("sent = %+v, want only 100.64.0.3", fwd.sent)
	}
	if !bytes.Contains(out.Bytes(), []byte("└─! Failed to send to 100.64.0.2: network unreachable")) {
		t.Errorf("output missing failure line:\n%s", out.String())
	}
}

func TestBuildUDP(t *testing.T) {
	src := netip.MustParseAddrPort("192.0.2.1:6112")
	dst := netip.MustParseAddrPort("192.0.2.2:6112")
	payload := []byte{0xF7, 0x2F, 0x10, 0x00, 'P', 'X', '3', 'W', 0x1A}

	b := BuildUDP(src, dst, payload)

	if got := binary.BigEndian.Uint16(b[0:2]); got != 6112 {
		t.Errorf("src port = %d", got)
	}
	if got := binary.BigEndian.Uint16(b[2:4]); got != 6112 {
		t.Errorf("dst port = %d", got)
	}
	if got := int(binary.BigEndian.Uint16(b[4:6])); got != udpHeaderLen+len(payload) {
		t.Errorf("length = %d", got)
	}
	if !bytes.Equal(b[udpHeaderLen:], payload) {
		t.Errorf("payload = %x", b[udpHeaderLen:])
	}

	// Verifying a correct checksum over pseudo-header + segment yields 0xffff.
	s, d := src.Addr().As4(), dst.Addr().As4()
	pseudo := append(append(s[:], d[:]...), 0, protoUDP, 0, byte(len(b)))
	if got := fold(checksum(checksum(0, pseudo), b)); got != 0xffff {
		t.Errorf("checksum verification = %#04x, want 0xffff", got)
	}
}

func TestChecksumKnownVector(t *testing.T) {
	// RFC 1071 section 3 example: 00 01 f2 03 f4 f5 f6 f7 sums to 0xddf2.
	if got := fold(checksum(0, []byte{0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7})); got != 0xddf2 {
		t.Errorf("checksum = %#04x, want 0xddf2", got)
	}
	if got := fold(checksum(0, []byte{0x01})); got != 0x0100 {
		t.Errorf("odd-length checksum = %#04x, want 0x0100", got)
	}
}

func TestBuildIPv4(t *testing.T) {
	src, dst := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.7")
	udp := BuildUDP(netip.AddrPortFrom(src, 6112), netip.AddrPortFrom(dst, 6112), []byte{0xF7, 0x2F, 0x10, 0x00})

	b := BuildIPv4(src, dst, 0x1234, udp)

	if len(b) != ipv4HeaderLen+len(udp) || b[0] != 0x45 {
		t.Fatalf("version/IHL = %#x, len = %d", b[0], len(b))
	}
	if got := int(binary.BigEndian.Uint16(b[2:4])); got != len(b) {
		t.Errorf("total length = %d, want %d", got, len(b))
	}
	if got := binary.BigEndian.Uint16(b[4:6]); got != 0x1234 {
		t.Errorf("identification = %#x", got)
	}
	if b[8] != defaultTTL || b[9] != protoUDP || binary.BigEndian.Uint16(b[6:8]) != 0 {
		t.Errorf("ttl/proto/frag = %d/%d/%#x", b[8], b[9], binary.BigEndian.Uint16(b[6:8]))
	}
	if !bytes.Equal(b[12:16], src.AsSlice()) || !bytes.Equal(b[16:20], dst.AsSlice()) {
		t.Errorf("addresses = % x / % x", b[12:16], b[16:20])
	}
	// A valid header checksums to 0xffff.
	if got := fold(checksum(0, b[:ipv4HeaderLen])); got != 0xffff {
		t.Errorf("header checksum verification = %#04x, want 0xffff", got)
	}
	if !bytes.Equal(b[ipv4HeaderLen:], udp) {
		t.Error("UDP segment not copied")
	}
}
