package settings

import (
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const fullYAML = `
mode: Relay
interface: wg0
peers:
  - 100.64.0.3
  - 100.64.0.2
  - 100.64.0.3
scan:
  enabled: false
  rate: 1000
  timeout: 2s
  network: 100.64.12.7/24
  min_prefix: 20
sniff:
  log_file: /tmp/wc3.log
  bin_file: /tmp/wc3.bin
`

func TestParseFull(t *testing.T) {
	cfg, err := Parse(strings.NewReader(fullYAML))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	want := Config{
		Mode:      ModeRelay,
		Interface: "wg0",
		Peers:     []netip.Addr{netip.MustParseAddr("100.64.0.2"), netip.MustParseAddr("100.64.0.3")},
		Scan: Scan{
			Enabled: false, Rate: 1000, Timeout: 2 * time.Second,
			Network: netip.MustParsePrefix("100.64.12.0/24"), MinPrefix: 20,
		},
		Sniff: Sniff{LogFile: "/tmp/wc3.log", BinFile: "/tmp/wc3.bin"},
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Errorf("Parse() =\n%+v\nwant\n%+v", cfg, want)
	}
}

func TestParsePartialKeepsDefaults(t *testing.T) {
	cfg, err := Parse(strings.NewReader("interface: utun4\n"))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	want := Default()
	want.Interface = "utun4"
	if !reflect.DeepEqual(cfg, want) {
		t.Errorf("Parse() = %+v, want %+v", cfg, want)
	}
}

func TestParseEmpty(t *testing.T) {
	cfg, err := Parse(strings.NewReader(""))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if !reflect.DeepEqual(cfg, Default()) {
		t.Errorf("Parse(\"\") = %+v, want defaults", cfg)
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{"unknown key", "modus: relay\n", "field modus not found"},
		{"bad mode", "mode: scan\n", "mode:"},
		{"bad peer", "peers: [not-an-ip]\n", "parse"},
		{"ipv6 peer", "peers: ['2001:db8::1']\n", "not an IPv4 address"},
		{"bad rate", "scan: {rate: 0}\n", "scan.rate"},
		{"bad timeout", "scan: {timeout: -1s}\n", "scan.timeout"},
		{"timeout not a duration", "scan: {timeout: soon}\n", "parse"},
		{"empty log file", "sniff: {log_file: ''}\n", "sniff.log_file"},
		{"min_prefix too small", "scan: {min_prefix: 10}\n", "scan.min_prefix"},
		{"min_prefix too big", "scan: {min_prefix: 33}\n", "scan.min_prefix"},
		{"network too large", "scan: {network: 100.64.0.0/10}\n", "too large"},
		{"network ipv6", "scan: {network: '2001:db8::/120'}\n", "not an IPv4 network"},
		{"network garbage", "scan: {network: nope}\n", "parse"},
		{"wrong type", "peers: 5\n", "parse"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(strings.NewReader(tt.yaml))
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Parse() error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "vpncraft", "config.yaml")
	cfg := Default()
	cfg.Mode = ModeRelay
	cfg.Peers = []netip.Addr{netip.MustParseAddr("100.64.0.9"), netip.MustParseAddr("100.64.0.2")}
	cfg.Scan.Timeout = 1500 * time.Millisecond
	cfg.Scan.Network = netip.MustParsePrefix("10.8.0.0/24")

	if err := Save(path, cfg); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "timeout: 1.5s") || !strings.Contains(string(raw), "- 100.64.0.2") ||
		!strings.Contains(string(raw), "network: 10.8.0.0/24") {
		t.Errorf("unexpected YAML:\n%s", raw)
	}

	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	want := cfg
	want.Peers = []netip.Addr{netip.MustParseAddr("100.64.0.2"), netip.MustParseAddr("100.64.0.9")}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Load() = %+v, want %+v", got, want)
	}

	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("config dir has %d entries, want 1 (no temp files left)", len(entries))
	}
}

func TestSaveRejectsInvalid(t *testing.T) {
	cfg := Default()
	cfg.Mode = "bogus"
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := Save(path, cfg); err == nil {
		t.Fatal("Save() error = nil for invalid config")
	}
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("invalid config was written: %v", err)
	}
}

func setHome(t *testing.T) (xdg, home string) {
	t.Helper()
	xdg, home = t.TempDir(), t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", xdg)
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // os.UserHomeDir on Windows
	return xdg, home
}

func TestPaths(t *testing.T) {
	xdg, home := setHome(t)
	want := []string{
		filepath.Join(xdg, "vpncraft", "config.yaml"),
		filepath.Join(home, ".config", "vpncraft", "config.yaml"),
	}
	if got := Paths(); !reflect.DeepEqual(got, want) {
		t.Errorf("Paths() = %v, want %v", got, want)
	}

	t.Setenv("XDG_CONFIG_HOME", "relative/path")
	if got := Paths(); !reflect.DeepEqual(got, want[1:]) {
		t.Errorf("Paths() with relative XDG = %v, want %v", got, want[1:])
	}
}

func TestResolve(t *testing.T) {
	xdg, home := setHome(t)
	xdgCfg := filepath.Join(xdg, "vpncraft", "config.yaml")
	homeCfg := filepath.Join(home, ".config", "vpncraft", "config.yaml")

	cfg, path, found, err := Resolve("")
	if err != nil || found || path != xdgCfg || !reflect.DeepEqual(cfg, Default()) {
		t.Fatalf("Resolve() = %+v, %q, %v, %v; want defaults with default path", cfg, path, found, err)
	}

	writeFile(t, homeCfg, "interface: home0\n")
	cfg, path, found, err = Resolve("")
	if err != nil || !found || path != homeCfg || cfg.Interface != "home0" {
		t.Fatalf("Resolve() = %q, %q, %v, %v; want home config", cfg.Interface, path, found, err)
	}

	writeFile(t, xdgCfg, "interface: xdg0\n")
	if cfg, path, _, _ = Resolve(""); path != xdgCfg || cfg.Interface != "xdg0" {
		t.Fatalf("Resolve() = %q from %q; want xdg config", cfg.Interface, path)
	}

	writeFile(t, xdgCfg, "mode: nope\n")
	if _, _, _, err = Resolve(""); err == nil {
		t.Fatal("Resolve() error = nil for invalid config")
	}

	if _, _, _, err = Resolve(filepath.Join(xdg, "missing.yaml")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Resolve(missing) error = %v, want ErrNotExist", err)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestExampleConfigIsValid(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "config.example.yaml"))
	if err != nil {
		t.Fatalf("config.example.yaml: %v", err)
	}
	if cfg.Mode != ModeRelay || len(cfg.Peers) != 2 {
		t.Errorf("unexpected example config: %+v", cfg)
	}
}

func TestDefaultHasNoInterface(t *testing.T) {
	cfg, err := Parse(strings.NewReader("mode: relay\n"))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if cfg.Interface != "" {
		t.Errorf("Interface = %q, want empty (no default)", cfg.Interface)
	}
}

func TestEmptyNetworkRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := Save(path, Default()); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got.Scan.Network.IsValid() || got.Scan.MinPrefix != DefaultMinPrefix {
		t.Errorf("scan = %+v", got.Scan)
	}
}

// TestSaveOverwrites covers replacing an existing file (second 'w' in the TUI),
// which uses os.Rename over the target; on Windows that is MoveFileEx with
// MOVEFILE_REPLACE_EXISTING.
func TestSaveOverwrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	first := Default()
	first.Interface = "wg0"
	if err := Save(path, first); err != nil {
		t.Fatalf("first Save() error = %v", err)
	}

	second := Default()
	second.Interface = "wt0"
	second.Mode = ModeRelay
	if err := Save(path, second); err != nil {
		t.Fatalf("second Save() error = %v", err)
	}

	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got.Interface != "wt0" || got.Mode != ModeRelay {
		t.Errorf("Load() = %+v, want second save", got)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("config dir has %d entries, want 1 (no temp files left)", len(entries))
	}
}
