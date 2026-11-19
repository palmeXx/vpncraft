package capture

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeReader replays scripted results, then idles like a read timeout.
type fakeReader struct {
	label  string
	script []readResult
	closed atomic.Bool
}

type readResult struct {
	pkt Packet
	ok  bool
	err error
}

func (f *fakeReader) read([]byte) (Packet, bool, error) {
	if len(f.script) == 0 {
		time.Sleep(time.Millisecond) // simulate a poll timeout
		return Packet{}, false, nil
	}
	r := f.script[0]
	f.script = f.script[1:]
	return r.pkt, r.ok, r.err
}

func (f *fakeReader) close() error { f.closed.Store(true); return nil }
func (f *fakeReader) name() string { return f.label }

func pkt(src, dst string, payload string) readResult {
	return readResult{
		pkt: Packet{Src: netip.MustParseAddrPort(src), Dst: netip.MustParseAddrPort(dst), Payload: []byte(payload)},
		ok:  true,
	}
}

// runUntil runs readers until want packets were handled, then cancels.
func runUntil(t *testing.T, readers []reader, want int) ([]string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var (
		mu  sync.Mutex
		got []string
	)
	err := run(ctx, readers, 6112, func(p Packet) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, string(p.Payload))
		if len(got) == want {
			cancel()
		}
	})
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("timed out, handled %v", got)
	}
	slices.Sort(got)
	return got, err
}

func TestRunFiltersByPort(t *testing.T) {
	r := &fakeReader{label: "fake0", script: []readResult{
		pkt("192.0.2.1:6112", "255.255.255.255:6112", "both"),
		pkt("192.0.2.1:50000", "192.0.2.2:6112", "dst"),
		pkt("192.0.2.1:6112", "192.0.2.2:50000", "src"),
		pkt("192.0.2.1:53", "192.0.2.2:53", "other-port"),
		{ok: false}, // timeout / undecodable frame
		pkt("192.0.2.1:6112", "192.0.2.2:6112", "last"),
	}}
	got, err := runUntil(t, []reader{r}, 4)
	if err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if want := []string{"both", "dst", "last", "src"}; !slices.Equal(got, want) {
		t.Errorf("handled %v, want %v", got, want)
	}
	if !r.closed.Load() {
		t.Error("reader not closed")
	}
}

func TestRunMultipleReadersSerializesHandle(t *testing.T) {
	var readers []reader
	for _, name := range []string{"a", "b", "c"} {
		var script []readResult
		for range 20 {
			script = append(script, pkt("192.0.2.1:6112", "192.0.2.2:6112", name))
		}
		readers = append(readers, &fakeReader{label: name, script: script})
	}

	var inHandle atomic.Int32
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var count atomic.Int32
	err := run(ctx, readers, 6112, func(Packet) {
		if inHandle.Add(1) != 1 {
			t.Error("handle called concurrently")
		}
		time.Sleep(10 * time.Microsecond)
		inHandle.Add(-1)
		if count.Add(1) == 60 {
			cancel()
		}
	})
	if err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if count.Load() != 60 {
		t.Errorf("handled %d packets, want 60", count.Load())
	}
	for _, r := range readers {
		if !r.(*fakeReader).closed.Load() {
			t.Errorf("reader %s not closed", r.name())
		}
	}
}

func TestRunReturnsReaderErrors(t *testing.T) {
	boom := errors.New("interface went away")
	readers := []reader{
		&fakeReader{label: "eth0", script: []readResult{pkt("192.0.2.1:6112", "192.0.2.2:6112", "x"), {err: boom}}},
		&fakeReader{label: "eth1", script: []readResult{{err: ErrPermission}}},
	}
	err := run(context.Background(), readers, 6112, func(Packet) {})
	if !errors.Is(err, boom) || !errors.Is(err, ErrPermission) {
		t.Fatalf("run() error = %v, want both reader errors", err)
	}
	for _, name := range []string{"capture on eth0", "capture on eth1"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error %q misses %q", err, name)
		}
	}
}

func TestRunCancelledIgnoresErrors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := &fakeReader{label: "eth0", script: []readResult{{err: errors.New("late")}}}
	if err := run(ctx, []reader{r}, 6112, func(Packet) {}); err != nil {
		t.Errorf("run() after cancel error = %v, want nil", err)
	}
	if !r.closed.Load() {
		t.Error("reader not closed")
	}
}

func TestInterfacesFor(t *testing.T) {
	all, err := interfacesFor(AllInterfaces)
	if err != nil {
		t.Fatalf("interfacesFor(all) error = %v", err)
	}
	if len(all) == 0 {
		t.Fatal("interfacesFor(all) returned no up interface")
	}
	one, err := interfacesFor(all[0].Name)
	if err != nil || len(one) != 1 || one[0].Name != all[0].Name {
		t.Errorf("interfacesFor(%q) = %v, %v", all[0].Name, one, err)
	}
	if _, err := interfacesFor("does-not-exist-0"); err == nil {
		t.Error("interfacesFor(unknown) error = nil")
	}
}
