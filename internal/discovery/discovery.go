// Package discovery finds live peers in an IPv4 range via an ICMP echo sweep.
//
// A single socket is used for the whole sweep: requests are sent at a fixed
// rate while a receiver goroutine collects replies, so scan time is bounded by
// len(targets)/Rate + Timeout instead of one round trip per host.
package discovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const (
	protocolICMP = 1
	maxPacket    = 1500
	pacingTick   = 10 * time.Millisecond
)

var echoData = []byte("VPNcraftPing")

// Options tunes a sweep. Zero values fall back to defaults.
type Options struct {
	// Rate is the maximum number of echo requests per second.
	Rate int
	// Timeout is how long to wait for replies after the last request.
	Timeout time.Duration
	// Progress, if set, is called periodically with sent/total/alive counters.
	Progress func(sent, total, alive int)
	// ProgressEvery controls how often (in sent packets) Progress is called.
	ProgressEvery int
}

func (o *Options) withDefaults(total int) {
	if o.Rate <= 0 {
		o.Rate = 5000
	}
	if o.Timeout <= 0 {
		o.Timeout = time.Second
	}
	if o.ProgressEvery <= 0 {
		o.ProgressEvery = 50
		if total > 5000 {
			o.ProgressEvery = 1000
		}
	}
}

// Listen opens a privileged raw ICMPv4 socket (root/Administrator required).
func Listen() (net.PacketConn, error) {
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, fmt.Errorf("open ICMP socket: %w", err)
	}
	return c, nil
}

// Sweep sends one echo request to each target over conn and returns the
// addresses that replied, sorted ascending. conn is not closed.
func Sweep(ctx context.Context, conn net.PacketConn, targets []netip.Addr, opts Options) ([]netip.Addr, error) {
	opts.withDefaults(len(targets))
	id := os.Getpid() & 0xffff

	wanted := make(map[netip.Addr]struct{}, len(targets))
	for _, t := range targets {
		wanted[t] = struct{}{}
	}

	var (
		mu    sync.Mutex
		alive = make(map[netip.Addr]struct{})
	)
	aliveCount := func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(alive)
	}

	recvDone := make(chan error, 1)
	go func() {
		recvDone <- receive(conn, id, func(src netip.Addr) {
			if _, ok := wanted[src]; !ok {
				return
			}
			mu.Lock()
			alive[src] = struct{}{}
			mu.Unlock()
		})
	}()

	// Unblock the receiver on cancellation.
	stop := context.AfterFunc(ctx, func() { _ = conn.SetReadDeadline(time.Now()) })
	defer stop()

	sendErr := send(ctx, conn, id, targets, opts, aliveCount)

	if sendErr == nil && ctx.Err() == nil {
		if err := conn.SetReadDeadline(time.Now().Add(opts.Timeout)); err != nil {
			sendErr = fmt.Errorf("set read deadline: %w", err)
		}
	}
	if sendErr != nil {
		_ = conn.SetReadDeadline(time.Now())
	}
	recvErr := <-recvDone

	mu.Lock()
	result := make([]netip.Addr, 0, len(alive))
	for a := range alive {
		result = append(result, a)
	}
	mu.Unlock()
	slices.SortFunc(result, netip.Addr.Compare)

	if err := errors.Join(sendErr, recvErr, ctx.Err()); err != nil {
		return result, err
	}
	return result, nil
}

func send(ctx context.Context, conn net.PacketConn, id int, targets []netip.Addr, opts Options, aliveCount func() int) error {
	burst := max(1, opts.Rate*int(pacingTick)/int(time.Second))
	ticker := time.NewTicker(pacingTick)
	defer ticker.Stop()

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &icmp.Echo{ID: id, Data: echoData},
	}
	echo := msg.Body.(*icmp.Echo)
	dst := &net.IPAddr{}

	for i, t := range targets {
		if i > 0 && i%burst == 0 {
			select {
			case <-ctx.Done():
				return nil // reported by caller via ctx.Err()
			case <-ticker.C:
			}
		}

		echo.Seq = i & 0xffff
		wb, err := msg.Marshal(nil)
		if err != nil {
			return fmt.Errorf("marshal echo request: %w", err)
		}
		dst.IP = t.AsSlice()
		if _, err := conn.WriteTo(wb, dst); err != nil {
			if errors.Is(err, net.ErrClosed) {
				return fmt.Errorf("send echo request: %w", err)
			}
			// Per-host failures (no route, host unreachable) are expected in a sweep.
		}

		sent := i + 1
		if opts.Progress != nil && (sent%opts.ProgressEvery == 0 || sent == len(targets)) {
			opts.Progress(sent, len(targets), aliveCount())
		}
	}
	return nil
}

// receive reads echo replies until the read deadline expires.
func receive(conn net.PacketConn, id int, onReply func(netip.Addr)) error {
	buf := make([]byte, maxPacket)
	for {
		n, peer, err := conn.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				return nil
			}
			return fmt.Errorf("read ICMP reply: %w", err)
		}
		msg, err := icmp.ParseMessage(protocolICMP, buf[:n])
		if err != nil || msg.Type != ipv4.ICMPTypeEchoReply {
			continue
		}
		echo, ok := msg.Body.(*icmp.Echo)
		if !ok || echo.ID != id {
			continue
		}
		ipAddr, ok := peer.(*net.IPAddr)
		if !ok {
			continue
		}
		if src, ok := netip.AddrFromSlice(ipAddr.IP); ok {
			onReply(src.Unmap())
		}
	}
}
