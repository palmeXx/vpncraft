// Package netutil resolves interfaces, their IPv4 network and scan ranges.
package netutil

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
)

// Network sources reported by DetectNetwork.
const (
	SourceInterface = "interface mask"
	SourceRoute     = "routing table"
)

var (
	// ErrNoIPv4 is returned when an interface has no usable IPv4 address.
	ErrNoIPv4 = errors.New("no IPv4 address on interface")
	// ErrNetworkUnknown is returned when neither the interface mask nor the
	// routing table reveal the network behind a host (/32) address.
	ErrNetworkUnknown = errors.New("network unknown: interface has a /32 address and no matching route")
)

// Route is an IPv4 route bound to an interface.
type Route struct {
	Dst     netip.Prefix
	IfIndex int
}

// InterfaceAddr returns the interface and its first IPv4 address with mask length.
func InterfaceAddr(iface string) (*net.Interface, netip.Prefix, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, netip.Prefix{}, fmt.Errorf("lookup interface %q: %w", iface, err)
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, netip.Prefix{}, fmt.Errorf("list addresses of %q: %w", iface, err)
	}
	if p := ipv4Prefixes(addrs); len(p) > 0 {
		return ifi, p[0], nil
	}
	return nil, netip.Prefix{}, fmt.Errorf("%q: %w", iface, ErrNoIPv4)
}

// DetectNetwork returns the local IPv4 address of iface and the network it
// belongs to, plus where that information came from. The interface mask is
// used when it describes a network (< /32); point-to-point tunnels (macOS utun,
// Tailscale, ...) report /32, so the most specific route through the interface
// that contains the local address is used instead.
func DetectNetwork(iface string) (netip.Addr, netip.Prefix, string, error) {
	ifi, addr, err := InterfaceAddr(iface)
	if err != nil {
		return netip.Addr{}, netip.Prefix{}, "", err
	}
	local := addr.Addr()
	if addr.Bits() > 0 && addr.Bits() < 32 {
		return local, addr.Masked(), SourceInterface, nil
	}

	routes, err := Routes()
	if err != nil {
		return local, netip.Prefix{}, "", fmt.Errorf("%q: read routing table: %w", iface, err)
	}
	if p, ok := NetworkFromRoutes(routes, ifi.Index, local); ok {
		return local, p, SourceRoute, nil
	}
	return local, netip.Prefix{}, "", fmt.Errorf("%q: %w", iface, ErrNetworkUnknown)
}

// NetworkFromRoutes picks the most specific route via ifIndex that contains
// local. Default routes and host routes are ignored.
func NetworkFromRoutes(routes []Route, ifIndex int, local netip.Addr) (netip.Prefix, bool) {
	var best netip.Prefix
	for _, r := range routes {
		bits := r.Dst.Bits()
		if r.IfIndex != ifIndex || bits <= 0 || bits >= 32 || !r.Dst.Addr().Is4() {
			continue
		}
		dst := r.Dst.Masked()
		if dst.Contains(local) && (!best.IsValid() || bits > best.Bits()) {
			best = dst
		}
	}
	return best, best.IsValid()
}

// HostCount returns the number of addresses Hosts would yield for p (before exclusion).
func HostCount(p netip.Prefix) uint64 {
	if !p.Addr().Is4() || p.Bits() < 0 {
		return 0
	}
	size := uint64(1) << (32 - p.Bits())
	if p.Bits() < 31 {
		size -= 2
	}
	return size
}

// Hosts returns all usable host addresses of an IPv4 prefix excluding the
// network and broadcast addresses (except for /31 and /32) and the given exclude address.
func Hosts(p netip.Prefix, exclude netip.Addr) []netip.Addr {
	p = p.Masked()
	if !p.Addr().Is4() {
		return nil
	}

	first := p.Addr()
	size := uint64(1) << (32 - p.Bits())
	skipEdges := p.Bits() < 31

	hosts := make([]netip.Addr, 0, size)
	a := first
	for i := range size {
		edge := i == 0 || i == size-1
		if (!skipEdges || !edge) && a != exclude {
			hosts = append(hosts, a)
		}
		a = a.Next()
	}
	return hosts
}
