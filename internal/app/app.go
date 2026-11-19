// Package app wires capture, discovery, relay and sniff into the two
// operation modes. It is shared by the headless CLI and the TUI.
package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/palmeXx/vpncraft/internal/capture"
	"github.com/palmeXx/vpncraft/internal/discovery"
	"github.com/palmeXx/vpncraft/internal/netutil"
	"github.com/palmeXx/vpncraft/internal/relay"
	"github.com/palmeXx/vpncraft/internal/settings"
	"github.com/palmeXx/vpncraft/internal/sniff"
	"github.com/palmeXx/vpncraft/internal/wc3"
)

// Progress reports the state of a running peer scan.
type Progress struct {
	Sent, Total, Alive int
	Elapsed            time.Duration
}

// ScanTarget describes the range a scan of an interface covers.
type ScanTarget struct {
	Local  netip.Addr
	Prefix netip.Prefix
	Source string // netutil.Source* or SourceConfig
	Hosts  []netip.Addr
}

// SourceConfig marks a scan range taken from scan.network.
const SourceConfig = "config scan.network"

// NetworkTooLargeError is returned when the detected network exceeds the
// configured scan limit (scan.min_prefix).
type NetworkTooLargeError struct {
	Iface     string
	Prefix    netip.Prefix
	Source    string
	MinPrefix int
}

func (e *NetworkTooLargeError) Error() string {
	hint := "set scan.network to the range to scan"
	if e.Prefix.Bits() >= settings.MaxScanBits {
		hint += " or lower scan.min_prefix"
	}
	return fmt.Sprintf("network %s of %s (from %s, %d hosts) is larger than the scan limit /%d; %s (e.g. %s)",
		e.Prefix, e.Iface, e.Source, netutil.HostCount(e.Prefix), e.MinPrefix, hint,
		netip.PrefixFrom(e.Prefix.Addr(), e.MinPrefix).Masked())
}

// PlanScan resolves the scan range of iface: scan.Network if set, otherwise
// the detected network if it is not larger than scan.MinPrefix.
func PlanScan(iface string, scan settings.Scan) (ScanTarget, error) {
	if scan.Network.IsValid() {
		var local netip.Addr
		if _, addr, err := netutil.InterfaceAddr(iface); err == nil {
			local = addr.Addr()
		}
		return ScanTarget{Local: local, Prefix: scan.Network, Source: SourceConfig, Hosts: netutil.Hosts(scan.Network, local)}, nil
	}

	local, prefix, source, err := netutil.DetectNetwork(iface)
	if err != nil {
		return ScanTarget{}, err
	}
	if prefix.Bits() < scan.MinPrefix {
		return ScanTarget{}, &NetworkTooLargeError{Iface: iface, Prefix: prefix, Source: source, MinPrefix: scan.MinPrefix}
	}
	return ScanTarget{Local: local, Prefix: prefix, Source: source, Hosts: netutil.Hosts(prefix, local)}, nil
}

// Scan ping-sweeps target and returns responding hosts, sorted.
func Scan(ctx context.Context, target ScanTarget, opts settings.Scan, progress func(Progress)) ([]netip.Addr, error) {
	conn, err := discovery.Listen()
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	start := time.Now()
	return discovery.Sweep(ctx, conn, target.Hosts, discovery.Options{
		Rate:    opts.Rate,
		Timeout: opts.Timeout,
		Progress: func(sent, total, alive int) {
			if progress != nil {
				progress(Progress{Sent: sent, Total: total, Alive: alive, Elapsed: time.Since(start)})
			}
		},
	})
}

// Run executes cfg.Mode until ctx is cancelled, logging to out. In relay mode
// with cfg.Scan.Enabled the peer group is extended by a scan of cfg.Interface.
func Run(ctx context.Context, cfg settings.Config, out io.Writer) error {
	if err := CheckInterface(cfg.Interface); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(out, "[*] WC3 Tool Started in [%s] Mode\n", strings.ToUpper(cfg.Mode))
	if cfg.Mode == settings.ModeRelay {
		return runRelay(ctx, cfg, out)
	}
	return runSniff(ctx, cfg, out)
}

func runSniff(ctx context.Context, cfg settings.Config, out io.Writer) error {
	_, _ = fmt.Fprintf(out, "[*] Sniffing on interface: '%s'\n", cfg.Interface)
	_, _ = fmt.Fprintf(out, "[*] Logging text to '%s' and raw bytes to '%s'\n", cfg.Sniff.LogFile, cfg.Sniff.BinFile)

	logger, err := sniff.NewLogger(out, cfg.Sniff.LogFile, cfg.Sniff.BinFile)
	if err != nil {
		return err
	}
	defer func() { _ = logger.Close() }()

	_, _ = fmt.Fprint(out, "[*] Press Ctrl+C to stop.\n\n")

	var writeErr error
	err = capture.Run(ctx, cfg.Interface, wc3.Port, func(pkt capture.Packet) {
		if err := logger.Handle(pkt); err != nil && writeErr == nil {
			writeErr = err
			_, _ = fmt.Fprintf(out, "[!] %v\n", err)
		}
	})
	return errors.Join(err, writeErr)
}

func runRelay(ctx context.Context, cfg settings.Config, out io.Writer) error {
	peers := slices.Clone(cfg.Peers)
	if cfg.Scan.Enabled {
		discovered, err := scanVerbose(ctx, cfg, out)
		if err != nil {
			return err
		}
		peers = append(peers, discovered...)
	}
	slices.SortFunc(peers, netip.Addr.Compare)
	peers = slices.Compact(peers)

	_, _ = fmt.Fprintf(out, "[*] Target VPN Interface: '%s'\n", cfg.Interface)
	_, _ = fmt.Fprintf(out, "[*] Forwarding to VPN peers (%d active): %s\n", len(peers), FormatAddrs(peers))
	if len(peers) == 0 {
		_, _ = fmt.Fprintln(out, "[!] Warning: No active peers found via ping!")
	}

	fwd, err := relay.NewRawForwarder(wc3.Port)
	if err != nil {
		return err
	}
	defer func() { _ = fwd.Close() }()

	r := relay.New(peers, wc3.Port, fwd, out)
	_, _ = fmt.Fprint(out, "[*] Press Ctrl+C to stop.\n\n")

	// Relay mode listens everywhere: local games broadcast on the LAN interface,
	// not on the VPN interface the peers are reached through.
	return capture.Run(ctx, capture.AllInterfaces, wc3.Port, r.Handle)
}

// scanVerbose scans cfg.Interface with console progress output. A missing
// subnet is not fatal: the static peer list is used instead.
func scanVerbose(ctx context.Context, cfg settings.Config, out io.Writer) ([]netip.Addr, error) {
	target, err := PlanScan(cfg.Interface, cfg.Scan)
	if err != nil {
		_, _ = fmt.Fprintf(out, "[!] Warning: Peer scan skipped: %v\n", err)
		_, _ = fmt.Fprintln(out, "    Using static peer list.")
		return nil, nil
	}
	_, _ = fmt.Fprintf(out, "[*] Detected local IP: %s on network %s (from %s)\n", target.Local, target.Prefix, target.Source)
	_, _ = fmt.Fprintf(out, "[*] Ping scanning /%d subnet range (%s, %d hosts)...\n", target.Prefix.Bits(), target.Prefix, len(target.Hosts))

	start := time.Now()
	found, err := Scan(ctx, target, cfg.Scan, func(p Progress) {
		_, _ = fmt.Fprintf(out, "\r[*] Progress: %d/%d hosts pinged (%.1fs) | Active peers: %d",
			p.Sent, p.Total, p.Elapsed.Seconds(), p.Alive)
	})
	_, _ = fmt.Fprintf(out, "\n[*] Dynamic /%d ICMP scan finished in %.2f seconds.\n", target.Prefix.Bits(), time.Since(start).Seconds())
	return found, err
}

// InterfaceNotFoundError reports a missing interface together with the likely
// VPN interfaces found instead. No interface is picked automatically.
type InterfaceNotFoundError struct {
	Name       string
	Candidates []netutil.NIC
}

func (e *InterfaceNotFoundError) Error() string {
	if e.Name == "" {
		return "no interface set: specify it with -i <name> or 'interface:' in the config file"
	}
	return fmt.Sprintf("interface %q not found: specify an existing interface with -i <name> or 'interface:' in the config file", e.Name)
}

// CheckInterface fails early for empty or unknown interfaces with an
// *InterfaceNotFoundError. AllInterfaces is always accepted.
func CheckInterface(name string) error {
	if strings.EqualFold(name, capture.AllInterfaces) {
		return nil
	}
	nics, err := netutil.ListNICs()
	if err != nil {
		return err
	}
	return checkInterface(name, nics)
}

func checkInterface(name string, nics []netutil.NIC) error {
	var vpn []netutil.NIC
	for _, n := range nics {
		if name != "" && n.Name == name {
			return nil
		}
		if n.VPN {
			vpn = append(vpn, n)
		}
	}
	return &InterfaceNotFoundError{Name: name, Candidates: vpn}
}

// FormatAddrs renders addresses as "[a, b]".
func FormatAddrs(addrs []netip.Addr) string {
	s := make([]string, len(addrs))
	for i, a := range addrs {
		s[i] = a.String()
	}
	return "[" + strings.Join(s, ", ") + "]"
}
