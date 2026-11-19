//go:build linux

package capture

import (
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestHtons(t *testing.T) {
	for _, v := range []uint16{0x0800, 0x0003, 0x1234, 0} {
		got := binary.NativeEndian.AppendUint16(nil, htons(v))
		want := binary.BigEndian.AppendUint16(nil, v)
		if string(got) != string(want) {
			t.Errorf("htons(%#04x) stored as % x, want % x", v, got, want)
		}
	}
}

func TestDuplicateLoopback(t *testing.T) {
	loopbacks := map[int]bool{1: true}
	tests := []struct {
		name string
		from unix.Sockaddr
		want bool
	}{
		{"outgoing on loopback", &unix.SockaddrLinklayer{Ifindex: 1, Pkttype: unix.PACKET_OUTGOING}, true},
		{"incoming on loopback", &unix.SockaddrLinklayer{Ifindex: 1, Pkttype: unix.PACKET_HOST}, false},
		{"outgoing on ethernet", &unix.SockaddrLinklayer{Ifindex: 2, Pkttype: unix.PACKET_OUTGOING}, false},
		{"broadcast on ethernet", &unix.SockaddrLinklayer{Ifindex: 2, Pkttype: unix.PACKET_BROADCAST}, false},
		{"not link layer", &unix.SockaddrInet4{}, false},
		{"nil", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := duplicateLoopback(tt.from, loopbacks); got != tt.want {
				t.Errorf("duplicateLoopback() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOpenUnknownInterface(t *testing.T) {
	_, err := open("does-not-exist-0", 6112)
	if err == nil || errors.Is(err, ErrPermission) {
		t.Errorf("open(unknown) error = %v, want lookup error", err)
	}
}

// TestOpen checks both outcomes: without CAP_NET_RAW the error must map to
// ErrPermission (drives the "run with sudo" hint); with it, the socket must
// open and honor the poll timeout.
func TestOpen(t *testing.T) {
	readers, err := open(AllInterfaces, 6112)
	if err != nil {
		if !errors.Is(err, ErrPermission) {
			t.Fatalf("open() error = %v, want ErrPermission when unprivileged", err)
		}
		t.Skip("no CAP_NET_RAW: permission mapping verified, socket path skipped")
	}
	t.Cleanup(func() { closeReaders(readers) })

	if len(readers) != 1 || readers[0].name() != AllInterfaces {
		t.Fatalf("open() = %d readers (%v), want one AF_PACKET socket for all interfaces", len(readers), readers)
	}
	pr := readers[0].(*packetReader)
	if len(pr.loopbacks) == 0 {
		t.Error("loopback interfaces not recorded")
	}

	start := time.Now()
	buf := make([]byte, readBufferSize)
	if _, _, err := pr.read(buf); err != nil {
		t.Fatalf("read() error = %v", err)
	}
	if d := time.Since(start); d > 4*pollInterval {
		t.Errorf("read() blocked %s, want at most ~%s", d, pollInterval)
	}
}

func closeReaders(rs []reader) {
	for _, r := range rs {
		_ = r.close()
	}
}
