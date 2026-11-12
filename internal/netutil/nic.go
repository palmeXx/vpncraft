package netutil

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
)

// vpnNamePrefixes are lower-case name prefixes of common VPN/overlay devices:
// NetBird (wt), WireGuard (wg), generic tun/tap, macOS utun, PPP, Tailscale,
// ZeroTier (zt), NordLynx and Hamachi.
var vpnNamePrefixes = []string{"wt", "wg", "tun", "tap", "utun", "ppp", "tailscale", "zt", "nordlynx", "ham", "netbird"}

// cgnat is RFC 6598 shared address space, used by NetBird and Tailscale overlays.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// NIC is a network interface as presented to the user.
type NIC struct {
	Name     string
	Addrs    []netip.Prefix // IPv4 only
	Up       bool
	Loopback bool
	// VPN marks interfaces that are likely VPN tunnels; VPNReason says why.
	VPN       bool
	VPNReason string
}

// ListNICs returns all interfaces, likely VPN interfaces first, then up
// interfaces with IPv4, then the rest; ties are ordered by name.
func ListNICs() ([]NIC, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}
	nics := make([]NIC, 0, len(ifaces))
	for _, ifi := range ifaces {
		nic := NIC{
			Name:     ifi.Name,
			Up:       ifi.Flags&net.FlagUp != 0,
			Loopback: ifi.Flags&net.FlagLoopback != 0,
		}
		if addrs, err := ifi.Addrs(); err == nil {
			nic.Addrs = ipv4Prefixes(addrs)
		}
		nic.VPN, nic.VPNReason = ClassifyVPN(nic.Name, ifi.Flags, nic.Addrs)
		nics = append(nics, nic)
	}
	SortNICs(nics)
	return nics, nil
}

// SortNICs orders VPN candidates first, then usable interfaces, then by name.
func SortNICs(nics []NIC) {
	rank := func(n NIC) int {
		switch {
		case n.VPN:
			return 0
		case n.Up && !n.Loopback && len(n.Addrs) > 0:
			return 1
		case n.Up && len(n.Addrs) > 0:
			return 2
		default:
			return 3
		}
	}
	slices.SortStableFunc(nics, func(a, b NIC) int {
		if d := rank(a) - rank(b); d != 0 {
			return d
		}
		return strings.Compare(a.Name, b.Name)
	})
}

// ClassifyVPN applies heuristics to decide whether an interface is likely a
// VPN tunnel. Only up, non-loopback interfaces with IPv4 qualify, which hides
// idle system tunnels such as macOS utun devices with link-local IPv6 only.
func ClassifyVPN(name string, flags net.Flags, addrs []netip.Prefix) (bool, string) {
	if flags&net.FlagUp == 0 || flags&net.FlagLoopback != 0 || len(addrs) == 0 {
		return false, ""
	}
	lower := strings.ToLower(name)
	for _, p := range vpnNamePrefixes {
		if strings.HasPrefix(lower, p) {
			return true, "name"
		}
	}
	for _, a := range addrs {
		if cgnat.Contains(a.Addr()) {
			return true, "100.64/10 address"
		}
	}
	if flags&net.FlagPointToPoint != 0 {
		return true, "point-to-point"
	}
	return false, ""
}

func ipv4Prefixes(addrs []net.Addr) []netip.Prefix {
	var out []netip.Prefix
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		addr, ok := netip.AddrFromSlice(ipNet.IP)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if !addr.Is4() {
			continue
		}
		ones, _ := ipNet.Mask.Size()
		out = append(out, netip.PrefixFrom(addr, ones))
	}
	return out
}
