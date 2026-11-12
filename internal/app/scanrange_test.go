package app

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/palmeXx/vpncraft/internal/settings"
)

func TestValidateScanRange(t *testing.T) {
	for p, ok := range map[string]bool{
		"100.64.0.0/24": true, "100.64.0.0/16": true, "10.0.0.1/32": true,
		"100.64.0.0/10": false, "2001:db8::/120": false,
	} {
		if err := ValidateScanRange(netip.MustParsePrefix(p)); (err == nil) != ok {
			t.Errorf("ValidateScanRange(%s) = %v, want ok=%v", p, err, ok)
		}
	}
}

func TestNewScanTarget(t *testing.T) {
	got := NewScanTarget(netip.MustParseAddr("192.0.2.1"), netip.MustParsePrefix("192.0.2.0/30"), "manual")
	if got.Source != "manual" || len(got.Hosts) != 1 || got.Hosts[0] != netip.MustParseAddr("192.0.2.2") {
		t.Errorf("NewScanTarget() = %+v", got)
	}
}

func TestScanOptionsUnknownInterface(t *testing.T) {
	if _, _, _, err := ScanOptions("does-not-exist-0", settings.Default().Scan); err == nil {
		t.Error("ScanOptions() error = nil for unknown interface")
	}
}

func TestScanOptions(t *testing.T) {
	local := netip.MustParseAddr("100.64.0.10")
	pfx := netip.MustParsePrefix
	tests := []struct {
		name       string
		detected   netip.Prefix
		configured netip.Prefix
		want       []string // prefix, "!" suffix = not allowed
		def        int
	}{
		{"tailscale /10", pfx("100.64.0.0/10"), netip.Prefix{}, []string{"100.64.0.0/10!", "100.64.0.0/16", "100.64.0.0/24"}, 1},
		{"netbird /16", pfx("100.64.0.0/16"), netip.Prefix{}, []string{"100.64.0.0/16", "100.64.0.0/24"}, 0},
		{"small /24", pfx("100.64.0.0/24"), netip.Prefix{}, []string{"100.64.0.0/24"}, 0},
		{"/20", pfx("100.64.0.0/20"), netip.Prefix{}, []string{"100.64.0.0/20", "100.64.0.0/24"}, 0},
		{"unknown", netip.Prefix{}, netip.Prefix{}, []string{"100.64.0.0/16", "100.64.0.0/24"}, 0},
		{"configured first", pfx("100.64.0.0/10"), pfx("100.64.7.0/24"), []string{"100.64.7.0/24", "100.64.0.0/10!", "100.64.0.0/16", "100.64.0.0/24"}, 0},
		{"configured equals detected", pfx("100.64.0.0/16"), pfx("100.64.0.0/16"), []string{"100.64.0.0/16", "100.64.0.0/24"}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts, def := scanOptions(local, tt.detected, "routing table", tt.configured)
			got := make([]string, len(opts))
			for i, o := range opts {
				got[i] = o.Prefix.String()
				if !o.Allowed {
					got[i] += "!"
				}
			}
			if !slices.Equal(got, tt.want) || def != tt.def {
				t.Errorf("scanOptions() = %v (default %d), want %v (default %d)", got, def, tt.want, tt.def)
			}
		})
	}
}
