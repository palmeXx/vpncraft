// Package relay forwards local Warcraft III LAN broadcasts to VPN peers.
package relay

import (
	"fmt"
	"io"
	"net/netip"
	"time"

	"github.com/palmeXx/vpncraft/internal/capture"
	"github.com/palmeXx/vpncraft/internal/wc3"
)

// TimeFormat matches the log timestamps of the original tool.
const TimeFormat = "2006-01-02 15:04:05"

// Forwarder delivers a UDP payload to a destination.
type Forwarder interface {
	Forward(payload []byte, dst netip.AddrPort) error
}

// Relay re-sends W3GS packets seen locally as unicast to every peer.
type Relay struct {
	peers   []netip.Addr
	peerSet map[netip.Addr]struct{}
	port    uint16
	fwd     Forwarder
	out     io.Writer
	now     func() time.Time
}

// New creates a Relay that forwards to peers on port via fwd and logs to out.
func New(peers []netip.Addr, port uint16, fwd Forwarder, out io.Writer) *Relay {
	set := make(map[netip.Addr]struct{}, len(peers))
	for _, p := range peers {
		set[p] = struct{}{}
	}
	return &Relay{peers: peers, peerSet: set, port: port, fwd: fwd, out: out, now: time.Now}
}

// Handle processes one captured datagram. Traffic from or to a peer is
// ignored, which also prevents re-forwarding our own relayed packets.
func (r *Relay) Handle(pkt capture.Packet) {
	if r.isPeer(pkt.Src.Addr()) || r.isPeer(pkt.Dst.Addr()) {
		return
	}
	if !wc3.IsW3GS(pkt.Payload) {
		return
	}

	_, _ = fmt.Fprintf(r.out, "[%s] [+] Caught local WC3 broadcast from %s -> %s\n",
		r.now().Format(TimeFormat), pkt.Src.Addr(), pkt.Dst.Addr())
	for _, peer := range r.peers {
		dst := netip.AddrPortFrom(peer, r.port)
		if err := r.fwd.Forward(pkt.Payload, dst); err != nil {
			_, _ = fmt.Fprintf(r.out, "    └─! Failed to send to %s: %v\n", peer, err)
			continue
		}
		_, _ = fmt.Fprintf(r.out, "    └─> Forwarded to %s\n", dst)
	}
}

func (r *Relay) isPeer(a netip.Addr) bool {
	_, ok := r.peerSet[a]
	return ok
}
