//go:build darwin

package capture

import (
	"encoding/binary"
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
