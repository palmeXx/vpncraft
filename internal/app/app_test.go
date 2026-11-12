package app

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/palmeXx/vpncraft/internal/netutil"
	"github.com/palmeXx/vpncraft/internal/settings"
)

func TestFormatAddrs(t *testing.T) {
	if got := FormatAddrs(nil); got != "[]" {
		t.Errorf("FormatAddrs(nil) = %q", got)
	}
	got := FormatAddrs([]netip.Addr{netip.MustParseAddr("100.64.0.2"), netip.MustParseAddr("100.64.0.3")})
	if got != "[100.64.0.2, 100.64.0.3]" {
		t.Errorf("FormatAddrs() = %q", got)
	}
}

func TestPlanScanUnknownInterface(t *testing.T) {
	if _, err := PlanScan("does-not-exist-0", settings.Default().Scan); err == nil {
		t.Error("PlanScan() error = nil for unknown interface")
	}
}

func TestCheckInterface(t *testing.T) {
	if err := CheckInterface("all"); err != nil {
		t.Errorf("CheckInterface(all) error = %v", err)
	}
	var nf *InterfaceNotFoundError
	if err := CheckInterface("does-not-exist-0"); !errors.As(err, &nf) || nf.Name != "does-not-exist-0" {
		t.Errorf("CheckInterface(unknown) error = %v", err)
	}
}

func TestCheckInterfaceCandidates(t *testing.T) {
	nics := []netutil.NIC{
		{Name: "utun4", VPN: true},
		{Name: "en0"},
		{Name: "wg0", VPN: true},
	}
	if err := checkInterface("en0", nics); err != nil {
		t.Errorf("checkInterface(en0) error = %v", err)
	}
	var nf *InterfaceNotFoundError
	if err := checkInterface("wt0", nics); !errors.As(err, &nf) {
		t.Fatalf("checkInterface(wt0) error = %v", err)
	}
	if len(nf.Candidates) != 2 || nf.Candidates[0].Name != "utun4" || nf.Candidates[1].Name != "wg0" {
		t.Errorf("candidates = %+v", nf.Candidates)
	}
}

func TestCheckInterfaceEmpty(t *testing.T) {
	var nf *InterfaceNotFoundError
	err := checkInterface("", []netutil.NIC{{Name: "utun4", VPN: true}})
	if !errors.As(err, &nf) || len(nf.Candidates) != 1 {
		t.Fatalf("checkInterface(\"\") error = %v", err)
	}
	if want := "no interface set"; !strings.Contains(err.Error(), want) {
		t.Errorf("error = %q, want containing %q", err, want)
	}
}

func TestPlanScanExplicitNetwork(t *testing.T) {
	scan := settings.Default().Scan
	scan.Network = netip.MustParsePrefix("192.0.2.0/30")
	got, err := PlanScan("does-not-exist-0", scan) // interface lookup is optional here
	if err != nil {
		t.Fatalf("PlanScan() error = %v", err)
	}
	if got.Source != SourceConfig || len(got.Hosts) != 2 {
		t.Errorf("PlanScan() = %+v", got)
	}
}

func TestNetworkTooLargeError(t *testing.T) {
	err := &NetworkTooLargeError{Iface: "utun4", Prefix: netip.MustParsePrefix("100.64.0.0/10"), Source: netutil.SourceRoute, MinPrefix: 24}
	for _, want := range []string{"100.64.0.0/10", "utun4", "routing table", "4194302 hosts", "/24", "scan.network", "100.64.0.0/24"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q misses %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "min_prefix") {
		t.Errorf("min_prefix cannot help for a /10: %q", err)
	}
	err.Prefix = netip.MustParsePrefix("10.8.0.0/20")
	if !strings.Contains(err.Error(), "lower scan.min_prefix") {
		t.Errorf("missing min_prefix hint for /20: %q", err)
	}
}

func TestLookupNames(t *testing.T) {
	lookup := func(_ context.Context, ip string) ([]string, error) {
		switch ip {
		case "100.64.0.2":
			return []string{"alice-pc.tailnet.example."}, nil
		case "100.64.0.3":
			return nil, nil
		default:
			return nil, errors.New("no PTR")
		}
	}
	got := lookupNames(context.Background(), addrs("100.64.0.2", "100.64.0.3", "100.64.0.4"), lookup)
	if len(got) != 1 || got[netip.MustParseAddr("100.64.0.2")] != "alice-pc.tailnet.example" {
		t.Errorf("lookupNames() = %v", got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := lookupNames(ctx, addrs("100.64.0.2"), lookup); len(got) > 1 {
		t.Errorf("cancelled lookupNames() = %v", got)
	}
}

func addrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParseAddr(s)
	}
	return out
}
