package netutil

import (
	"errors"
	"net"
	"net/netip"
	"testing"
)

func TestNetworkFromRoutes(t *testing.T) {
	local := netip.MustParseAddr("100.64.0.10")
	routes := []Route{
		{Dst: netip.MustParsePrefix("0.0.0.0/0"), IfIndex: 23},          // default via VPN (exit node)
		{Dst: netip.MustParsePrefix("100.64.0.0/10"), IfIndex: 23},      // overlay network
		{Dst: netip.MustParsePrefix("100.64.0.10/32"), IfIndex: 23},     // own host route
		{Dst: netip.MustParsePrefix("100.64.0.0/24"), IfIndex: 5},       // other interface
		{Dst: netip.MustParsePrefix("10.48.16.0/24"), IfIndex: 23},      // subnet route, not ours
		{Dst: netip.MustParsePrefix("100.100.100.100/32"), IfIndex: 23}, // MagicDNS
	}
	got, ok := NetworkFromRoutes(routes, 23, local)
	if !ok || got != netip.MustParsePrefix("100.64.0.0/10") {
		t.Errorf("NetworkFromRoutes() = %s, %v; want 100.64.0.0/10", got, ok)
	}

	routes = append(routes, Route{Dst: netip.MustParsePrefix("100.64.0.0/16"), IfIndex: 23})
	if got, _ := NetworkFromRoutes(routes, 23, local); got != netip.MustParsePrefix("100.64.0.0/16") {
		t.Errorf("most specific route not chosen: %s", got)
	}

	if _, ok := NetworkFromRoutes(routes, 23, netip.MustParseAddr("192.0.2.1")); ok {
		t.Error("route found for address outside all routes")
	}
	if _, ok := NetworkFromRoutes(routes, 99, local); ok {
		t.Error("route found for unknown interface")
	}
	unmasked := []Route{{Dst: netip.PrefixFrom(local, 24), IfIndex: 1}}
	if got, _ := NetworkFromRoutes(unmasked, 1, local); got != netip.MustParsePrefix("100.64.0.0/24") {
		t.Errorf("unmasked route = %s, want masked", got)
	}
}

func TestHostCount(t *testing.T) {
	for p, want := range map[string]uint64{
		"100.64.0.0/10": 4194302, "10.0.0.0/24": 254, "10.0.0.0/31": 2, "10.0.0.1/32": 1, "2001:db8::/64": 0,
	} {
		if got := HostCount(netip.MustParsePrefix(p)); got != want {
			t.Errorf("HostCount(%s) = %d, want %d", p, got, want)
		}
	}
}

func TestRoutes(t *testing.T) {
	routes, err := Routes()
	if err != nil {
		t.Fatalf("Routes() error = %v", err)
	}
	for _, r := range routes {
		if !r.Dst.Addr().Is4() {
			t.Errorf("non-IPv4 route %v", r)
		}
	}

	// Every supported OS has a 127.0.0.0/8 route on the loopback interface.
	// Finding it verifies address, prefix length and interface index decoding.
	lo := loopbackIndex(t)
	local := netip.MustParseAddr("127.0.0.1")
	if _, ok := NetworkFromRoutes(routes, lo, local); !ok {
		t.Fatalf("no route containing %s via loopback (index %d) in %d routes", local, lo, len(routes))
	}
}

func loopbackIndex(t *testing.T) int {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagLoopback != 0 && ifi.Flags&net.FlagUp != 0 {
			return ifi.Index
		}
	}
	t.Skip("no loopback interface")
	return 0
}

func TestDetectNetworkLoopback(t *testing.T) {
	nics, err := ListNICs()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nics {
		if n.Loopback && len(n.Addrs) > 0 && n.Addrs[0].Bits() < 32 {
			local, p, src, err := DetectNetwork(n.Name)
			if err != nil || src != SourceInterface || !p.Contains(local) {
				t.Errorf("DetectNetwork(%s) = %s, %s, %q, %v", n.Name, local, p, src, err)
			}
			return
		}
	}
	t.Skip("no loopback interface with IPv4 network")
}

func TestHosts(t *testing.T) {
	tests := []struct {
		name    string
		prefix  string
		exclude string
		want    []string
	}{
		{"slash30", "192.0.2.0/30", "0.0.0.0", []string{"192.0.2.1", "192.0.2.2"}},
		{"slash29 exclude self", "192.0.2.8/29", "192.0.2.10", []string{"192.0.2.9", "192.0.2.11", "192.0.2.12", "192.0.2.13", "192.0.2.14"}},
		{"slash31 keeps edges", "192.0.2.4/31", "0.0.0.0", []string{"192.0.2.4", "192.0.2.5"}},
		{"unmasked input", "192.0.2.7/30", "0.0.0.0", []string{"192.0.2.5", "192.0.2.6"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Hosts(netip.MustParsePrefix(tt.prefix), netip.MustParseAddr(tt.exclude))
			if len(got) != len(tt.want) {
				t.Fatalf("Hosts() = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i].String() != tt.want[i] {
					t.Errorf("Hosts()[%d] = %s, want %s", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestHostsSlash16Count(t *testing.T) {
	got := Hosts(netip.MustParsePrefix("100.64.0.0/16"), netip.MustParseAddr("100.64.0.1"))
	if want := 65534 - 1; len(got) != want {
		t.Errorf("len(Hosts(/16)) = %d, want %d", len(got), want)
	}
}

func TestHostsIPv6(t *testing.T) {
	if got := Hosts(netip.MustParsePrefix("2001:db8::/126"), netip.Addr{}); got != nil {
		t.Errorf("Hosts(IPv6) = %v, want nil", got)
	}
}

func TestDetectNetworkUnknownInterface(t *testing.T) {
	_, _, _, err := DetectNetwork("does-not-exist-0")
	if err == nil {
		t.Fatal("expected error for unknown interface")
	}
	if errors.Is(err, ErrNoIPv4) {
		t.Errorf("unexpected ErrNoIPv4 for unknown interface: %v", err)
	}
}
