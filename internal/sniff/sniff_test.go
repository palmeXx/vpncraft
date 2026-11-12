package sniff

import (
	"bytes"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/palmeXx/vpncraft/internal/capture"
)

var fixedTime = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func w3Packet(payload ...byte) capture.Packet {
	return capture.Packet{
		Src:     netip.MustParseAddrPort("192.0.2.10:6112"),
		Dst:     netip.MustParseAddrPort("255.255.255.255:6112"),
		Payload: payload,
	}
}

func TestFormatEntry(t *testing.T) {
	got := FormatEntry(fixedTime, w3Packet(0xF7, 0x2F, 0x10, 0x00))
	want := "[2026-01-02 03:04:05] Captured 4 bytes from 192.0.2.10:6112\n" +
		"Payload (Hex):\n" +
		"f7 2f 10 00\n" +
		"Decoded Message:\n" +
		"Host IP Address: 192.0.2.10\n" +
		"Packet ID: 0x2F | Declared Length: 16 bytes\n" +
		"ASCII Stream: ./..\n" +
		separator + "\n"
	if got != want {
		t.Errorf("FormatEntry() =\n%s\nwant\n%s", got, want)
	}
}

func TestHexSpaced(t *testing.T) {
	for in, want := range map[string]string{"": "", "\x00": "00", "\xab\x01\xff": "ab 01 ff"} {
		if got := hexSpaced([]byte(in)); got != want {
			t.Errorf("hexSpaced(%x) = %q, want %q", in, got, want)
		}
	}
}

func TestLoggerWritesFiles(t *testing.T) {
	dir := t.TempDir()
	textPath := filepath.Join(dir, "wc3.log")
	binPath := filepath.Join(dir, "wc3.bin")

	// Existing content must be preserved (append mode).
	if err := os.WriteFile(binPath, []byte{0xAA}, 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	l, err := NewLogger(&out, textPath, binPath)
	if err != nil {
		t.Fatalf("NewLogger() error = %v", err)
	}
	l.now = func() time.Time { return fixedTime }

	for _, pkt := range []capture.Packet{
		w3Packet(0xF7, 0x2F, 0x10, 0x00),
		w3Packet(0x01, 0x02, 0x03, 0x04), // ignored: not W3GS
		w3Packet(0xF7, 0x30, 0x04, 0x00),
	} {
		if err := l.Handle(pkt); err != nil {
			t.Fatalf("Handle() error = %v", err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	bin, err := os.ReadFile(binPath)
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{0xAA, 0xF7, 0x2F, 0x10, 0x00, 0xF7, 0x30, 0x04, 0x00}; !bytes.Equal(bin, want) {
		t.Errorf("binary dump = %x, want %x", bin, want)
	}

	text, err := os.ReadFile(textPath)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(text), separator); n != 2 {
		t.Errorf("log file has %d entries, want 2", n)
	}
	if n := strings.Count(out.String(), "Captured 4 bytes"); n != 2 {
		t.Errorf("stdout has %d entries, want 2", n)
	}
}

func TestNewLoggerBadPath(t *testing.T) {
	dir := t.TempDir()
	if _, err := NewLogger(&bytes.Buffer{}, filepath.Join(dir, "missing", "x.log"), filepath.Join(dir, "x.bin")); err == nil {
		t.Error("NewLogger() error = nil for unwritable text path")
	}
	if _, err := NewLogger(&bytes.Buffer{}, filepath.Join(dir, "x.log"), filepath.Join(dir, "missing", "x.bin")); err == nil {
		t.Error("NewLogger() error = nil for unwritable binary path")
	}
}
