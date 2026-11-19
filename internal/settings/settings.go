// Package settings loads, validates and saves the vpncraft YAML configuration.
//
// Lookup order (first existing file wins, unless a path is given explicitly):
//
//	$XDG_CONFIG_HOME/vpncraft/config.yaml
//	~/.config/vpncraft/config.yaml
//
// The same XDG layout is used on Linux, macOS and Windows.
package settings

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// Operation modes.
const (
	ModeSniff = "sniff"
	ModeRelay = "relay"
)

const (
	appDir   = "vpncraft"
	fileName = "config.yaml"
	dirPerm  = 0o755
	filePerm = 0o644
)

// Config is the complete runtime configuration.
type Config struct {
	Mode      string       `yaml:"mode"`
	Interface string       `yaml:"interface"`
	Peers     []netip.Addr `yaml:"peers"`
	Scan      Scan         `yaml:"scan"`
	Sniff     Sniff        `yaml:"sniff"`
}

// Scan configures ICMP peer discovery.
type Scan struct {
	Enabled bool          `yaml:"enabled"`
	Rate    int           `yaml:"rate"`
	Timeout time.Duration `yaml:"timeout"`
	// Network overrides the detected scan range (empty: detect from the
	// interface mask or routing table). It is not subject to MinPrefix.
	Network netip.Prefix `yaml:"network"`
	// MinPrefix is the largest detected network that is scanned automatically,
	// as prefix length (24 = at most a /24).
	MinPrefix int `yaml:"min_prefix"`
}

// Scan range bounds. /16 (65534 hosts) keeps a sweep within seconds to minutes.
const (
	MaxScanBits      = 16
	DefaultMinPrefix = 24
)

// Sniff configures the output files of sniff mode.
type Sniff struct {
	LogFile string `yaml:"log_file"`
	BinFile string `yaml:"bin_file"`
}

// Default returns the built-in defaults.
func Default() Config {
	return Config{
		Mode: ModeSniff,
		// Interface has no default: it must come from a flag or the config
		// file (checked before running, see app.CheckInterface).
		Scan:  Scan{Enabled: true, Rate: 5000, Timeout: time.Second, MinPrefix: DefaultMinPrefix},
		Sniff: Sniff{LogFile: "wc3_broadcasts.log", BinFile: "wc3_packets.bin"},
	}
}

// Validate checks semantic constraints and normalizes Mode and Peers
// (lower-case mode, sorted and de-duplicated peers).
func (c *Config) Validate() error {
	var errs []error

	c.Mode = strings.ToLower(c.Mode)
	if c.Mode != ModeSniff && c.Mode != ModeRelay {
		errs = append(errs, fmt.Errorf("mode: %q is invalid (want %q or %q)", c.Mode, ModeSniff, ModeRelay))
	}
	c.Interface = strings.TrimSpace(c.Interface)
	for _, p := range c.Peers {
		if !p.Is4() {
			errs = append(errs, fmt.Errorf("peers: %s is not an IPv4 address", p))
		}
	}
	if c.Scan.Rate <= 0 {
		errs = append(errs, fmt.Errorf("scan.rate: must be positive, got %d", c.Scan.Rate))
	}
	if c.Scan.Timeout <= 0 {
		errs = append(errs, fmt.Errorf("scan.timeout: must be positive, got %s", c.Scan.Timeout))
	}
	if c.Scan.MinPrefix < MaxScanBits || c.Scan.MinPrefix > 32 {
		errs = append(errs, fmt.Errorf("scan.min_prefix: must be between %d and 32, got %d", MaxScanBits, c.Scan.MinPrefix))
	}
	if n := c.Scan.Network; n.IsValid() {
		switch {
		case !n.Addr().Is4():
			errs = append(errs, fmt.Errorf("scan.network: %s is not an IPv4 network", n))
		case n.Bits() < MaxScanBits:
			errs = append(errs, fmt.Errorf("scan.network: %s is too large (at most /%d)", n, MaxScanBits))
		default:
			c.Scan.Network = n.Masked()
		}
	}
	if c.Sniff.LogFile == "" {
		errs = append(errs, errors.New("sniff.log_file: must not be empty"))
	}
	if c.Sniff.BinFile == "" {
		errs = append(errs, errors.New("sniff.bin_file: must not be empty"))
	}

	slices.SortFunc(c.Peers, netip.Addr.Compare)
	c.Peers = slices.Compact(c.Peers)
	return errors.Join(errs...)
}

// Parse decodes YAML on top of the defaults and validates the result.
// Unknown keys are rejected to catch typos early.
func Parse(r io.Reader) (Config, error) {
	cfg := Default()
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return Config{}, fmt.Errorf("parse: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Load reads and validates the file at path.
func Load(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer func() { _ = f.Close() }()

	cfg, err := Parse(f)
	if err != nil {
		return Config{}, fmt.Errorf("config %s: %w", path, err)
	}
	return cfg, nil
}

// Save validates cfg and writes it atomically to path, creating parent directories.
func Save(path string, cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	var buf bytes.Buffer
	buf.WriteString("# vpncraft configuration – written by vpncraft\n")
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(cfg); err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	if err := enc.Close(); err != nil {
		return fmt.Errorf("encode config: %w", err)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, fileName+".*.tmp")
	if err != nil {
		return fmt.Errorf("create temp config: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // no-op after successful rename

	if _, err := tmp.Write(buf.Bytes()); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write config: %w", err)
	}
	if err := tmp.Chmod(filePerm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("replace config: %w", err)
	}
	return nil
}

// Paths returns candidate config file locations in lookup order.
func Paths() []string {
	var paths []string
	// Per XDG spec, relative values are invalid and ignored.
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" && filepath.IsAbs(xdg) {
		paths = append(paths, filepath.Join(xdg, appDir, fileName))
	}
	if home, err := os.UserHomeDir(); err == nil {
		p := filepath.Join(home, ".config", appDir, fileName)
		if !slices.Contains(paths, p) {
			paths = append(paths, p)
		}
	}
	return paths
}

// DefaultPath is where a new config file is written.
func DefaultPath() (string, error) {
	paths := Paths()
	if len(paths) == 0 {
		return "", errors.New("cannot determine config directory: neither XDG_CONFIG_HOME nor a home directory is set")
	}
	return paths[0], nil
}

// Resolve returns the configuration to use and the file it came from.
// With an explicit path the file must exist. Otherwise the first existing
// candidate from Paths is loaded; if none exists, defaults are returned with
// found=false and path set to DefaultPath (empty if undeterminable).
func Resolve(explicit string) (cfg Config, path string, found bool, err error) {
	if explicit != "" {
		cfg, err := Load(explicit)
		if err != nil {
			return Config{}, explicit, false, err
		}
		return cfg, explicit, true, nil
	}
	for _, p := range Paths() {
		cfg, err := Load(p)
		switch {
		case err == nil:
			return cfg, p, true, nil
		case errors.Is(err, fs.ErrNotExist):
			continue
		default:
			return Config{}, p, false, err
		}
	}
	path, _ = DefaultPath()
	return Default(), path, false, nil
}
