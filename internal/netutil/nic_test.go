package netutil

import (
	"net"
	"net/netip"
	"testing"
)

func prefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

func TestClassifyVPN(t *testing.T) {
	up := net.FlagUp
	tests := []struct {
		name   string
		iface  string
		flags  net.Flags
		addrs  []netip.Prefix
		want   bool
		reason string
	}{
		{"netbird", "wt0", up, prefixes("100.88.1.2/16"), true, "name"},
		{"wireguard", "wg0", up, prefixes("10.8.0.2/24"), true, "name"},
		{"tailscale windows", "Tailscale", up, prefixes("100.101.1.1/32"), true, "name"},
		{"cgnat address", "eth5", up, prefixes("100.70.0.1/16"), true, "100.64/10 address"},
		{"point to point", "gif0", up | net.FlagPointToPoint, prefixes("10.0.0.1/32"), true, "point-to-point"},
		{"lan", "en0", up | net.FlagBroadcast, prefixes("192.168.1.20/24"), false, ""},
		{"idle utun without ipv4", "utun3", up | net.FlagPointToPoint, nil, false, ""},
		{"down tunnel", "wt0", 0, prefixes("100.88.1.2/16"), false, ""},
		{"loopback", "lo0", up | net.FlagLoopback, prefixes("127.0.0.1/8"), false, ""},
		{"outside cgnat", "eth0", up, prefixes("100.128.0.1/16"), false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, reason := ClassifyVPN(tt.iface, tt.flags, tt.addrs)
			if got != tt.want || reason != tt.reason {
				t.Errorf("ClassifyVPN() = %v, %q; want %v, %q", got, reason, tt.want, tt.reason)
			}
		})
	}
}

func TestSortNICs(t *testing.T) {
	nics := []NIC{
		{Name: "lo0", Up: true, Loopback: true, Addrs: prefixes("127.0.0.1/8")},
		{Name: "gif0"},
		{Name: "en1", Up: true, Addrs: prefixes("10.0.0.2/24")},
		{Name: "wt0", Up: true, VPN: true, Addrs: prefixes("100.88.1.2/16")},
		{Name: "en0", Up: true, Addrs: prefixes("192.168.1.2/24")},
	}
	SortNICs(nics)
	want := []string{"wt0", "en0", "en1", "lo0", "gif0"}
	for i, n := range nics {
		if n.Name != want[i] {
			t.Fatalf("order = %v, want %v", names(nics), want)
		}
	}
}

func names(nics []NIC) []string {
	out := make([]string, len(nics))
	for i, n := range nics {
		out[i] = n.Name
	}
	return out
}

func TestListNICs(t *testing.T) {
	nics, err := ListNICs()
	if err != nil {
		t.Fatalf("ListNICs() error = %v", err)
	}
	if len(nics) == 0 {
		t.Fatal("ListNICs() returned no interfaces")
	}
	for _, n := range nics {
		for _, a := range n.Addrs {
			if !a.Addr().Is4() {
				t.Errorf("%s: non-IPv4 address %s", n.Name, a)
			}
		}
	}
}
