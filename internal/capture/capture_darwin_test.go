//go:build darwin

package capture

import (
	"encoding/binary"
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

func bpfRecord(frame []byte) []byte {
	rec := make([]byte, unix.SizeofBpfHdr, unix.SizeofBpfHdr+len(frame)+bpfAlignment)
	binary.NativeEndian.PutUint32(rec[8:], uint32(len(frame)))
	binary.NativeEndian.PutUint32(rec[12:], uint32(len(frame)))
	binary.NativeEndian.PutUint16(rec[16:], unix.SizeofBpfHdr)
	rec = append(rec, frame...)
	for len(rec)%bpfAlignment != 0 {
		rec = append(rec, 0)
	}
	return rec
}

func TestNextBPFFrame(t *testing.T) {
	buf := append(bpfRecord([]byte("abc")), bpfRecord([]byte("defgh"))...)

	frame, rest, ok := nextBPFFrame(buf)
	if !ok || string(frame) != "abc" {
		t.Fatalf("first frame = %q, %v", frame, ok)
	}
	frame, rest, ok = nextBPFFrame(rest)
	if !ok || string(frame) != "defgh" {
		t.Fatalf("second frame = %q, %v", frame, ok)
	}
	if len(rest) != 0 {
		t.Errorf("rest = %d bytes, want 0", len(rest))
	}
}

func TestNextBPFFrameTruncated(t *testing.T) {
	rec := bpfRecord([]byte("abcdef"))
	if _, _, ok := nextBPFFrame(rec[:unix.SizeofBpfHdr+2]); ok {
		t.Error("nextBPFFrame() ok = true for truncated record")
	}
	if _, _, ok := nextBPFFrame(rec[:4]); ok {
		t.Error("nextBPFFrame() ok = true for short header")
	}
}

func TestOpenUnknownInterface(t *testing.T) {
	_, err := open("does-not-exist-0", 6112)
	if err == nil || errors.Is(err, ErrPermission) {
		t.Errorf("open(unknown) error = %v, want lookup error", err)
	}
}

// TestOpen checks both outcomes: without root, /dev/bpf access must map to
// ErrPermission; as root, one BPF reader per capable interface must open.
func TestOpen(t *testing.T) {
	readers, err := open(AllInterfaces, 6112)
	if err != nil {
		if !errors.Is(err, ErrPermission) {
			t.Fatalf("open() error = %v, want ErrPermission when unprivileged", err)
		}
		t.Skip("no /dev/bpf access: permission mapping verified, socket path skipped")
	}
	t.Cleanup(func() { closeAll(readers) })
	if len(readers) == 0 {
		t.Fatal("open() returned no readers")
	}
}
