//go:build windows

package capture

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestSioRcvAllValue(t *testing.T) {
	// SIO_RCVALL = _WSAIOW(IOC_VENDOR, 1) = 0x98000001 (mstcpip.h).
	if sioRcvAll != 0x98000001 {
		t.Errorf("sioRcvAll = %#x, want 0x98000001", sioRcvAll)
	}
}

func TestIsTransientRecvErr(t *testing.T) {
	tests := []struct {
		err  error
		want bool
	}{
		{windows.WSAETIMEDOUT, true},
		{windows.WSAEMSGSIZE, true},
		{fmt.Errorf("recvfrom: %w", windows.WSAETIMEDOUT), true},
		{windows.WSAENETDOWN, false},
		{windows.WSAEACCES, false},
		{errors.New("other"), false},
	}
	for _, tt := range tests {
		if got := isTransientRecvErr(tt.err); got != tt.want {
			t.Errorf("isTransientRecvErr(%v) = %v, want %v", tt.err, got, tt.want)
		}
	}
}

func TestOpenUnknownInterface(t *testing.T) {
	_, err := open("does-not-exist-0", 6112)
	if err == nil || errors.Is(err, ErrPermission) {
		t.Errorf("open(unknown) error = %v, want lookup error", err)
	}
}

// TestOpen checks both outcomes: without Administrator rights the error must
// map to ErrPermission; with them, one SIO_RCVALL socket per non-loopback
// IPv4 address must open and honor the poll timeout.
func TestOpen(t *testing.T) {
	readers, err := open(AllInterfaces, 6112)
	if err != nil {
		if !errors.Is(err, ErrPermission) {
			t.Fatalf("open() error = %v, want ErrPermission when not elevated", err)
		}
		t.Skip("not elevated: permission mapping verified, socket path skipped")
	}
	t.Cleanup(func() { closeAll(readers) })

	if len(readers) == 0 {
		t.Fatal("open() returned no readers")
	}
	loopbacks := loopbackNames(t)
	for _, r := range readers {
		for _, lo := range loopbacks {
			if strings.HasPrefix(r.name(), lo+" (") {
				t.Errorf("reader %q opened on loopback", r.name())
			}
		}
	}

	start := time.Now()
	buf := make([]byte, readBufferSize)
	if _, _, err := readers[0].read(buf); err != nil {
		t.Fatalf("read() error = %v", err)
	}
	if d := time.Since(start); d > 4*pollInterval {
		t.Errorf("read() blocked %s, want at most ~%s", d, pollInterval)
	}
}

func loopbackNames(t *testing.T) []string {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagLoopback != 0 {
			names = append(names, ifi.Name)
		}
	}
	return names
}
