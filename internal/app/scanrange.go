package app

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/palmeXx/vpncraft/internal/netutil"
	"github.com/palmeXx/vpncraft/internal/settings"
)

// Standard sub-ranges offered around the local address, largest first.
var standardBits = []int{16, 24}

// ScanOption is one selectable scan range.
type ScanOption struct {
	Prefix   netip.Prefix
	Label    string // e.g. "detected (routing table)", "/24 around local IP"
	Detected bool   // the auto-detected network; selecting it means "detect"
	Allowed  bool   // false if larger than settings.MaxScanBits
}

// Hosts is the number of addresses the option covers.
func (o ScanOption) Hosts() uint64 { return netutil.HostCount(o.Prefix) }

// ScanOptions lists scan ranges for iface: the configured scan.network, the
// detected network and the standard /16 and /24 networks containing the local
// address that are smaller than the detected one. def is the preselected
// index: the configured range, else the detected one if allowed, else the
// first allowed option.
func ScanOptions(iface string, scan settings.Scan) (local netip.Addr, opts []ScanOption, def int, err error) {
	local, detected, source, err := netutil.DetectNetwork(iface)
	if err != nil && !errors.Is(err, netutil.ErrNetworkUnknown) {
		return netip.Addr{}, nil, 0, err
	}
	opts, def = scanOptions(local, detected, source, scan.Network)
	return local, opts, def, nil
}

// scanOptions builds the option list; detected may be invalid (unknown).
func scanOptions(local netip.Addr, detected netip.Prefix, source string, configured netip.Prefix) (opts []ScanOption, def int) {
	seen := make(map[netip.Prefix]bool)
	add := func(o ScanOption) {
		if seen[o.Prefix] {
			return
		}
		seen[o.Prefix] = true
		o.Allowed = o.Prefix.Bits() >= settings.MaxScanBits
		opts = append(opts, o)
	}

	if configured.IsValid() {
		add(ScanOption{Prefix: configured, Label: "configured (scan.network)"})
	}
	if detected.IsValid() {
		add(ScanOption{Prefix: detected, Label: fmt.Sprintf("detected (%s)", source), Detected: true})
	}
	for _, bits := range standardBits {
		if detected.IsValid() && bits <= detected.Bits() {
			continue
		}
		add(ScanOption{Prefix: netip.PrefixFrom(local, bits).Masked(), Label: fmt.Sprintf("/%d around local IP", bits)})
	}

	def = -1
	for i, o := range opts {
		if o.Allowed && (def < 0 || (!configured.IsValid() && o.Detected)) {
			def = i
		}
	}
	return opts, max(def, 0)
}

// NewScanTarget builds the target for an explicitly chosen range.
func NewScanTarget(local netip.Addr, prefix netip.Prefix, source string) ScanTarget {
	return ScanTarget{Local: local, Prefix: prefix, Source: source, Hosts: netutil.Hosts(prefix, local)}
}

// ValidateScanRange checks a user-supplied range.
func ValidateScanRange(p netip.Prefix) error {
	switch {
	case !p.Addr().Is4():
		return fmt.Errorf("%s is not an IPv4 network", p)
	case p.Bits() < settings.MaxScanBits:
		return fmt.Errorf("%s is too large (%d hosts, at most /%d)", p.Masked(), netutil.HostCount(p), settings.MaxScanBits)
	}
	return nil
}
