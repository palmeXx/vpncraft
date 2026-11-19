package discovery

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// fakeICMP answers echo requests for a fixed set of live hosts.
type fakeICMP struct {
	live    map[netip.Addr]bool
	replies chan reply

	mu       sync.Mutex
	deadline time.Time
	wake     chan struct{}
	sent     int
}

type reply struct {
	from netip.Addr
	data []byte
}

func newFakeICMP(live ...string) *fakeICMP {
	f := &fakeICMP{
		live:    make(map[netip.Addr]bool),
		replies: make(chan reply, 1024),
		wake:    make(chan struct{}, 1),
	}
	for _, l := range live {
		f.live[netip.MustParseAddr(l)] = true
	}
	return f
}

func (f *fakeICMP) WriteTo(b []byte, addr net.Addr) (int, error) {
	f.mu.Lock()
	f.sent++
	f.mu.Unlock()

	msg, err := icmp.ParseMessage(protocolICMP, b)
	if err != nil {
		return 0, err
	}
	echo := msg.Body.(*icmp.Echo)
	dst, _ := netip.AddrFromSlice(addr.(*net.IPAddr).IP)
	if !f.live[dst] {
		return len(b), nil
	}
	resp := icmp.Message{Type: ipv4.ICMPTypeEchoReply, Body: &icmp.Echo{ID: echo.ID, Seq: echo.Seq, Data: echo.Data}}
	rb, err := resp.Marshal(nil)
	if err != nil {
		return 0, err
	}
	f.replies <- reply{from: dst, data: rb}
	return len(b), nil
}

func (f *fakeICMP) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		f.mu.Lock()
		dl := f.deadline
		f.mu.Unlock()

		var timeout <-chan time.Time
		if !dl.IsZero() {
			d := time.Until(dl)
			if d <= 0 {
				return 0, nil, os.ErrDeadlineExceeded
			}
			timer := time.NewTimer(d)
			defer timer.Stop()
			timeout = timer.C
		}

		select {
		case r := <-f.replies:
			return copy(b, r.data), &net.IPAddr{IP: r.from.AsSlice()}, nil
		case <-timeout:
			return 0, nil, os.ErrDeadlineExceeded
		case <-f.wake:
			// deadline changed, re-evaluate
		}
	}
}

func (f *fakeICMP) SetReadDeadline(t time.Time) error {
	f.mu.Lock()
	f.deadline = t
	f.mu.Unlock()
	select {
	case f.wake <- struct{}{}:
	default:
	}
	return nil
}

func (f *fakeICMP) Close() error                     { return nil }
func (f *fakeICMP) LocalAddr() net.Addr              { return &net.IPAddr{} }
func (f *fakeICMP) SetDeadline(t time.Time) error    { return f.SetReadDeadline(t) }
func (f *fakeICMP) SetWriteDeadline(time.Time) error { return nil }

func addrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParseAddr(s)
	}
	return out
}

func TestSweepFindsLiveHosts(t *testing.T) {
	conn := newFakeICMP("192.0.2.3", "192.0.2.1", "198.51.100.1") // last one is not a target
	targets := addrs("192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4")

	var progressCalls int
	got, err := Sweep(context.Background(), conn, targets, Options{
		Timeout:       50 * time.Millisecond,
		ProgressEvery: 2,
		Progress:      func(_, _, _ int) { progressCalls++ },
	})
	if err != nil {
		t.Fatalf("Sweep() error = %v", err)
	}
	if want := addrs("192.0.2.1", "192.0.2.3"); !slices.Equal(got, want) {
		t.Errorf("Sweep() = %v, want %v", got, want)
	}
	if conn.sent != len(targets) {
		t.Errorf("sent %d requests, want %d", conn.sent, len(targets))
	}
	if progressCalls != 2 {
		t.Errorf("progress called %d times, want 2", progressCalls)
	}
}

func TestSweepIgnoresForeignEchoID(t *testing.T) {
	conn := newFakeICMP()
	foreign := icmp.Message{Type: ipv4.ICMPTypeEchoReply, Body: &icmp.Echo{ID: (os.Getpid() + 1) & 0xffff, Data: echoData}}
	b, err := foreign.Marshal(nil)
	if err != nil {
		t.Fatal(err)
	}
	conn.replies <- reply{from: netip.MustParseAddr("192.0.2.1"), data: b}

	got, err := Sweep(context.Background(), conn, addrs("192.0.2.1"), Options{Timeout: 20 * time.Millisecond})
	if err != nil {
		t.Fatalf("Sweep() error = %v", err)
	}
	if len(got) != 0 {
		t.Errorf("Sweep() = %v, want none", got)
	}
}

func TestSweepCancel(t *testing.T) {
	conn := newFakeICMP()
	targets := make([]netip.Addr, 0, 1000)
	a := netip.MustParseAddr("10.0.0.1")
	for range 1000 {
		targets = append(targets, a)
		a = a.Next()
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	_, err := Sweep(ctx, conn, targets, Options{Rate: 100, Timeout: time.Hour})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Sweep() error = %v, want context.Canceled", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("cancelled sweep took %s", elapsed)
	}
}
