package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"

	"github.com/palmeXx/vpncraft/internal/settings"
)

var errHelp = errors.New("help requested")

// options are the parsed command line. Fields only take effect if the
// corresponding flag was set, so flags override the config file.
type options struct {
	configPath  string
	headless    bool
	showVersion bool
	set         map[string]bool

	mode          string
	iface         string
	noScan        bool
	peers         peerList
	logFile       string
	binFile       string
	scanRate      int
	scanTimeout   time.Duration
	scanNetwork   string
	scanMinPrefix int
}

// peerList implements flag.Value for a comma-separated list of IPv4 addresses.
type peerList []netip.Addr

func (p *peerList) String() string {
	s := make([]string, len(*p))
	for i, a := range *p {
		s[i] = a.String()
	}
	return strings.Join(s, ",")
}

func (p *peerList) Set(v string) error {
	for field := range strings.SplitSeq(v, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		a, err := netip.ParseAddr(field)
		if err != nil || !a.Is4() {
			return fmt.Errorf("invalid IPv4 peer %q", field)
		}
		*p = append(*p, a)
	}
	return nil
}

// flag aliases: short form -> canonical name, used to track which settings were given.
var flagAliases = map[string]string{"m": "mode", "i": "interface"}

func parseFlags(args []string, output io.Writer) (options, error) {
	def := settings.Default()
	opts := options{set: make(map[string]bool)}

	fs := flag.NewFlagSet("vpncraft", flag.ContinueOnError)
	fs.SetOutput(output)
	fs.Usage = func() {
		paths := strings.Join(settings.Paths(), "\n  ")
		_, _ = fmt.Fprintf(output, "Warcraft III LAN Packet Sniffer & UDP Relay for VPNs\n\n"+
			"Usage: vpncraft [flags]\n\n"+
			"Without arguments in a terminal, the interactive TUI starts.\n"+
			"Any flag (except -config) runs headless. Flags override the config file:\n  %s\n\nFlags:\n", paths)
		fs.PrintDefaults()
	}

	fs.StringVar(&opts.configPath, "config", "", "config file (default: first existing of the paths above)")
	fs.BoolVar(&opts.headless, "headless", false, "run without TUI using the config file only")
	fs.BoolVar(&opts.showVersion, "version", false, "print version information and exit")

	const modeHelp = "operation mode: 'sniff' logs packets, 'relay' forwards broadcasts"
	fs.StringVar(&opts.mode, "mode", def.Mode, modeHelp)
	fs.StringVar(&opts.mode, "m", def.Mode, "shorthand for -mode")
	const ifaceHelp = "network interface for relay/sniffing, required via flag or config ('all' sniffs every interface)"
	fs.StringVar(&opts.iface, "interface", def.Interface, ifaceHelp)
	fs.StringVar(&opts.iface, "i", def.Interface, "shorthand for -interface")
	fs.BoolVar(&opts.noScan, "no-scan", false, "disable auto-scanning the subnet for active ICMP peers in relay mode")
	fs.Var(&opts.peers, "peers", "comma-separated peer IPv4 addresses (replaces the config's peer group)")
	fs.StringVar(&opts.logFile, "log-file", def.Sniff.LogFile, "text log file for sniff mode")
	fs.StringVar(&opts.binFile, "bin-file", def.Sniff.BinFile, "raw payload dump for sniff mode")
	fs.IntVar(&opts.scanRate, "scan-rate", def.Scan.Rate, "maximum ICMP echo requests per second during peer scan")
	fs.DurationVar(&opts.scanTimeout, "scan-timeout", def.Scan.Timeout, "time to wait for ICMP replies after the last request")
	fs.StringVar(&opts.scanNetwork, "scan-network", "", "explicit scan range as CIDR, e.g. 100.64.12.0/24 (default: detect)")
	fs.IntVar(&opts.scanMinPrefix, "scan-min-prefix", def.Scan.MinPrefix, "largest detected network to scan automatically, as prefix length")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return opts, errHelp
		}
		return opts, err
	}
	if fs.NArg() > 0 {
		return opts, fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	fs.Visit(func(f *flag.Flag) {
		name := f.Name
		if canonical, ok := flagAliases[name]; ok {
			name = canonical
		}
		opts.set[name] = true
	})
	return opts, nil
}

// interactive reports whether the TUI should start: no flag other than -config.
func (o options) interactive() bool {
	for name := range o.set {
		if name != "config" {
			return false
		}
	}
	return true
}

// apply overlays explicitly set flags onto cfg and validates the result.
func (o options) apply(cfg settings.Config) (settings.Config, error) {
	if o.set["mode"] {
		cfg.Mode = o.mode
	}
	if o.set["interface"] {
		cfg.Interface = o.iface
	}
	if o.set["no-scan"] {
		cfg.Scan.Enabled = !o.noScan
	}
	if o.set["peers"] {
		cfg.Peers = append([]netip.Addr(nil), o.peers...)
	}
	if o.set["log-file"] {
		cfg.Sniff.LogFile = o.logFile
	}
	if o.set["bin-file"] {
		cfg.Sniff.BinFile = o.binFile
	}
	if o.set["scan-rate"] {
		cfg.Scan.Rate = o.scanRate
	}
	if o.set["scan-timeout"] {
		cfg.Scan.Timeout = o.scanTimeout
	}
	if o.set["scan-network"] {
		p, err := netip.ParsePrefix(o.scanNetwork)
		if err != nil {
			return cfg, fmt.Errorf("scan-network: %w", err)
		}
		cfg.Scan.Network = p
	}
	if o.set["scan-min-prefix"] {
		cfg.Scan.MinPrefix = o.scanMinPrefix
	}
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}
