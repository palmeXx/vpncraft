// Package capture passively captures IPv4/UDP datagrams for a port without
// binding it, so it can run next to an application that owns the port.
//
// Implementations are CGO-free: AF_PACKET on Linux, /dev/bpf on macOS and
// SIO_RCVALL raw sockets on Windows. All require root/Administrator.
package capture

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// AllInterfaces selects every capable interface.
const AllInterfaces = "all"

// pollInterval bounds how long a blocking read waits before re-checking ctx.
const pollInterval = 250 * time.Millisecond

// ErrPermission is returned when the OS refuses raw capture access.
var ErrPermission = errors.New("root/Administrator privileges required")

// reader is a single platform capture handle.
type reader interface {
	// read blocks for at most pollInterval. ok is false on timeout or for
	// frames that are not matching IPv4/UDP datagrams.
	read(buf []byte) (pkt Packet, ok bool, err error)
	close() error
	name() string
}

// Run captures UDP datagrams to or from port on iface (or AllInterfaces) and
// calls handle for each one until ctx is cancelled. handle is never called
// concurrently and must copy Payload if it retains it.
func Run(ctx context.Context, iface string, port uint16, handle func(Packet)) error {
	readers, err := open(iface, port)
	if err != nil {
		return err
	}
	if len(readers) == 0 {
		return fmt.Errorf("no capturable interface for %q", iface)
	}
	return run(ctx, readers, port, handle)
}

// run multiplexes readers until ctx is cancelled or every reader failed.
// All readers are closed on return.
func run(ctx context.Context, readers []reader, port uint16, handle func(Packet)) error {
	var (
		wg      sync.WaitGroup
		handleM sync.Mutex
		errs    = make([]error, len(readers))
	)
	for i, r := range readers {
		wg.Go(func() {
			defer func() { _ = r.close() }()
			buf := make([]byte, readBufferSize)
			for ctx.Err() == nil {
				pkt, ok, err := r.read(buf)
				if err != nil {
					errs[i] = fmt.Errorf("capture on %s: %w", r.name(), err)
					return
				}
				if !ok || pkt.Src.Port() != port && pkt.Dst.Port() != port {
					continue
				}
				handleM.Lock()
				handle(pkt)
				handleM.Unlock()
			}
		})
	}
	wg.Wait()

	if ctx.Err() != nil {
		return nil
	}
	return errors.Join(errs...)
}

// interfacesFor resolves iface to the list of up interfaces to capture on.
func interfacesFor(iface string) ([]net.Interface, error) {
	if !strings.EqualFold(iface, AllInterfaces) {
		ifi, err := net.InterfaceByName(iface)
		if err != nil {
			return nil, fmt.Errorf("lookup interface %q: %w", iface, err)
		}
		return []net.Interface{*ifi}, nil
	}
	all, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}
	up := all[:0]
	for _, ifi := range all {
		if ifi.Flags&net.FlagUp != 0 {
			up = append(up, ifi)
		}
	}
	return up, nil
}
