package main

import (
	"bytes"
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/palmeXx/vpncraft/internal/app"
	"github.com/palmeXx/vpncraft/internal/netutil"
	"github.com/palmeXx/vpncraft/internal/settings"
)

func mustParse(t *testing.T, args ...string) options {
	t.Helper()
	opts, err := parseFlags(args, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("parseFlags(%v) error = %v", args, err)
	}
	return opts
}

func TestApplyWithoutFlagsKeepsConfig(t *testing.T) {
	file := settings.Default()
	file.Mode = settings.ModeRelay
	file.Interface = "wg0"
	file.Peers = []netip.Addr{netip.MustParseAddr("100.64.0.9")}

	cfg, err := mustParse(t).apply(file)
	if err != nil {
		t.Fatalf("apply() error = %v", err)
	}
	if !reflect.DeepEqual(cfg, file) {
		t.Errorf("apply() = %+v, want unchanged %+v", cfg, file)
	}
}

func TestApplyFlagsOverrideConfig(t *testing.T) {
	file := settings.Default()
	file.Peers = []netip.Addr{netip.MustParseAddr("100.64.0.9")}

	opts := mustParse(t,
		"-m", "RELAY", "--interface", "wg0", "--no-scan",
		"-peers", "100.64.0.3, 100.64.0.2", "-peers", "100.64.0.4",
		"-scan-rate", "100", "-scan-timeout", "2s", "-log-file", "a.log", "-bin-file", "a.bin",
		"-scan-network", "100.64.12.9/24", "-scan-min-prefix", "20",
	)
	cfg, err := opts.apply(file)
	if err != nil {
		t.Fatalf("apply() error = %v", err)
	}
	want := settings.Config{
		Mode:      settings.ModeRelay,
		Interface: "wg0",
		Peers: []netip.Addr{
			netip.MustParseAddr("100.64.0.2"),
			netip.MustParseAddr("100.64.0.3"),
			netip.MustParseAddr("100.64.0.4"),
		},
		Scan: settings.Scan{
			Enabled: false, Rate: 100, Timeout: 2 * time.Second,
			Network: netip.MustParsePrefix("100.64.12.0/24"), MinPrefix: 20,
		},
		Sniff: settings.Sniff{LogFile: "a.log", BinFile: "a.bin"},
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Errorf("apply() =\n%+v\nwant\n%+v", cfg, want)
	}
}

func TestInteractive(t *testing.T) {
	tests := []struct {
		args []string
		want bool
	}{
		{nil, true},
		{[]string{"-config", "x.yaml"}, true},
		{[]string{"-headless"}, false},
		{[]string{"-m", "relay"}, false},
		{[]string{"-no-scan"}, false},
	}
	for _, tt := range tests {
		if got := mustParse(t, tt.args...).interactive(); got != tt.want {
			t.Errorf("interactive(%v) = %v, want %v", tt.args, got, tt.want)
		}
	}
}

func TestParseFlagsErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"ipv6 peer", []string{"-peers", "2001:db8::1"}},
		{"garbage peer", []string{"-peers", "not-an-ip"}},
		{"positional args", []string{"extra"}},
		{"unknown flag", []string{"-x"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseFlags(tt.args, &bytes.Buffer{}); err == nil {
				t.Errorf("parseFlags(%v) error = nil", tt.args)
			}
		})
	}
}

func TestApplyValidates(t *testing.T) {
	for _, args := range [][]string{
		{"-m", "scan"}, {"-scan-rate", "0"}, {"-scan-timeout", "-1s"},
		{"-scan-network", "nope"}, {"-scan-network", "100.64.0.0/10"}, {"-scan-min-prefix", "8"},
	} {
		if _, err := mustParse(t, args...).apply(settings.Default()); err == nil {
			t.Errorf("apply(%v) error = nil", args)
		}
	}
}

// isolateConfig points config lookup at an empty temp home.
func isolateConfig(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	return filepath.Join(home, ".config", "vpncraft", "config.yaml")
}

func TestRunVersion(t *testing.T) {
	isolateConfig(t)
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"-version"}, &stdout, &stderr, false); code != 0 {
		t.Fatalf("run() = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "vpncraft dev (commit unknown") {
		t.Errorf("stdout = %q", stdout.String())
	}
}

func TestRunHelpAndBadFlags(t *testing.T) {
	isolateConfig(t)
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"-h"}, &stdout, &stderr, false); code != 0 {
		t.Errorf("run(-h) = %d, want 0", code)
	}
	if !strings.Contains(stderr.String(), "Usage: vpncraft") {
		t.Errorf("help output = %q", stderr.String())
	}
	if code := run(context.Background(), []string{"-m", "bogus"}, &stdout, &stderr, false); code != 2 {
		t.Errorf("run(-m bogus) = %d, want 2", code)
	}
}

func TestRunRejectsInvalidConfigFile(t *testing.T) {
	path := isolateConfig(t)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("mode: nope\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"-headless"}, &stdout, &stderr, false); code != 2 {
		t.Errorf("run() = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "Invalid configuration") || !strings.Contains(stderr.String(), path) {
		t.Errorf("stderr = %q", stderr.String())
	}
}

func TestRunMissingExplicitConfig(t *testing.T) {
	isolateConfig(t)
	var stdout, stderr bytes.Buffer
	missing := filepath.Join(t.TempDir(), "missing.yaml")
	if code := run(context.Background(), []string{"-config", missing, "-headless"}, &stdout, &stderr, false); code != 2 {
		t.Errorf("run() = %d, want 2", code)
	}
}

func TestWriteInterfaceHint(t *testing.T) {
	utun := netutil.NIC{
		Name: "utun4", VPN: true, VPNReason: "name",
		Addrs: []netip.Prefix{netip.MustParsePrefix("100.64.0.10/32")},
	}
	tests := []struct {
		name  string
		err   *app.InterfaceNotFoundError
		path  string
		found bool
		want  []string
	}{
		{
			name: "no config yet",
			err:  &app.InterfaceNotFoundError{Name: "wt0", Candidates: []netutil.NIC{utun}},
			path: "/home/u/.config/vpncraft/config.yaml",
			want: []string{
				`interface "wt0" not found`, "utun4", "100.64.0.10/32",
				"create the config file /home/u/.config/vpncraft/config.yaml", "interface: utun4", "-i utun4",
			},
		},
		{
			name:  "existing config",
			err:   &app.InterfaceNotFoundError{Name: "wt0", Candidates: []netutil.NIC{utun}},
			path:  "/etc/x.yaml",
			found: true,
			want:  []string{"Set it in your config /etc/x.yaml", "interface: utun4"},
		},
		{
			name: "no candidates",
			err:  &app.InterfaceNotFoundError{Name: "wt0"},
			want: []string{"No likely VPN interface found"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var b bytes.Buffer
			writeInterfaceHint(&b, tt.err, tt.path, tt.found)
			for _, w := range tt.want {
				if !strings.Contains(b.String(), w) {
					t.Errorf("hint misses %q:\n%s", w, b.String())
				}
			}
		})
	}
}

func TestRunUnknownInterfaceExitCode(t *testing.T) {
	isolateConfig(t)
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"-i", "does-not-exist-0"}, &stdout, &stderr, false); code != 2 {
		t.Errorf("run() = %d, want 2; stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), `interface "does-not-exist-0" not found`) {
		t.Errorf("stderr = %q", stderr.String())
	}
}

func TestRunWithoutInterface(t *testing.T) {
	isolateConfig(t)
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"-headless"}, &stdout, &stderr, false); code != 2 {
		t.Errorf("run() = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "no interface set") || !strings.Contains(stderr.String(), "-i <name>") {
		t.Errorf("stderr = %q", stderr.String())
	}
}
