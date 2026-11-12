package capture

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

// buildIPv4UDP returns a minimal IPv4/UDP packet from 192.0.2.1 (no checksums).
func buildIPv4UDP(dst string, sport, dport uint16, payload []byte) []byte {
	b := make([]byte, 28+len(payload))
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	b[8] = 64
	b[9] = protoUDP
	s, d := netip.MustParseAddr("192.0.2.1").As4(), netip.MustParseAddr(dst).As4()
	copy(b[12:], s[:])
	copy(b[16:], d[:])
	binary.BigEndian.PutUint16(b[20:], sport)
	binary.BigEndian.PutUint16(b[22:], dport)
	binary.BigEndian.PutUint16(b[24:], uint16(8+len(payload)))
	copy(b[28:], payload)
	return b
}

func ethernet(etherType uint16, vlan bool, ip []byte) []byte {
	hdr := make([]byte, 12, 18)
	if vlan {
		hdr = binary.BigEndian.AppendUint16(hdr, etherTypeVLAN)
		hdr = binary.BigEndian.AppendUint16(hdr, 7)
	}
	hdr = binary.BigEndian.AppendUint16(hdr, etherType)
	return append(hdr, ip...)
}

func TestDecodeIPv4UDP(t *testing.T) {
	payload := []byte{0xF7, 0x2F, 0x10, 0x00}
	pkt := buildIPv4UDP("255.255.255.255", 6112, 6112, payload)

	got, ok := DecodeIPv4UDP(pkt)
	if !ok {
		t.Fatal("DecodeIPv4UDP() ok = false")
	}
	if got.Src != netip.MustParseAddrPort("192.0.2.1:6112") || got.Dst != netip.MustParseAddrPort("255.255.255.255:6112") {
		t.Errorf("addresses = %s -> %s", got.Src, got.Dst)
	}
	if !bytes.Equal(got.Payload, payload) {
		t.Errorf("payload = %x, want %x", got.Payload, payload)
	}
}

func TestDecodeIPv4UDPRejects(t *testing.T) {
	valid := func() []byte { return buildIPv4UDP("192.0.2.2", 1, 2, []byte("x")) }

	tests := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"truncated", func(b []byte) []byte { return b[:19] }},
		{"ipv6", func(b []byte) []byte { b[0] = 0x60; return b }},
		{"tcp", func(b []byte) []byte { b[9] = 6; return b }},
		{"bad ihl", func(b []byte) []byte { b[0] = 0x44; return b }},
		{"non-first fragment", func(b []byte) []byte { b[7] = 1; return b }},
		{"no udp header", func(b []byte) []byte { return b[:24] }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, ok := DecodeIPv4UDP(tt.mutate(valid())); ok {
				t.Error("DecodeIPv4UDP() ok = true, want false")
			}
		})
	}
}

func TestDecodeIPv4UDPLengthFallback(t *testing.T) {
	b := buildIPv4UDP("192.0.2.2", 1, 2, []byte("abc"))
	binary.BigEndian.PutUint16(b[2:], 0)     // IP total length unset (offload)
	binary.BigEndian.PutUint16(b[24:], 9999) // bogus UDP length
	got, ok := DecodeIPv4UDP(b)
	if !ok || string(got.Payload) != "abc" {
		t.Errorf("DecodeIPv4UDP() = %q, %v; want \"abc\", true", got.Payload, ok)
	}
}

func TestDecodeFrame(t *testing.T) {
	ip := buildIPv4UDP("192.0.2.2", 6112, 6112, []byte("w3"))
	le := binary.LittleEndian.AppendUint32(nil, afInet)
	be := binary.BigEndian.AppendUint32(nil, afInet)

	tests := []struct {
		name  string
		link  LinkType
		frame []byte
		ok    bool
	}{
		{"raw", LinkRaw, ip, true},
		{"null little endian", LinkNull, append(le, ip...), true},
		{"loop big endian", LinkLoop, append(be, ip...), true},
		{"null ipv6 family", LinkNull, append([]byte{30, 0, 0, 0}, ip...), false},
		{"null truncated", LinkNull, []byte{2, 0}, false},
		{"ethernet", LinkEthernet, ethernet(etherTypeIPv4, false, ip), true},
		{"ethernet vlan", LinkEthernet, ethernet(etherTypeIPv4, true, ip), true},
		{"ethernet arp", LinkEthernet, ethernet(0x0806, false, ip), false},
		{"ethernet truncated", LinkEthernet, ip[:10], false},
		{"unknown link", LinkType(999), ip, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := DecodeFrame(tt.link, tt.frame)
			if ok != tt.ok {
				t.Fatalf("DecodeFrame() ok = %v, want %v", ok, tt.ok)
			}
			if ok && string(got.Payload) != "w3" {
				t.Errorf("payload = %q, want %q", got.Payload, "w3")
			}
		})
	}
}

func FuzzDecodeIPv4UDP(f *testing.F) {
	f.Add(buildIPv4UDP("192.0.2.2", 6112, 6112, []byte{0xF7, 0x2F}))
	f.Fuzz(func(_ *testing.T, b []byte) {
		_, _ = DecodeIPv4UDP(b)
	})
}
