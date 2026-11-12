//go:build darwin

package netutil

import (
	"fmt"
	"math/bits"
	"net/netip"
	"syscall"

	"golang.org/x/net/route"
)

// Routes reads the IPv4 routing table via sysctl(NET_RT_DUMP).
func Routes() ([]Route, error) {
	rib, err := route.FetchRIB(syscall.AF_INET, route.RIBTypeRoute, 0)
	if err != nil {
		return nil, fmt.Errorf("fetch RIB: %w", err)
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil, fmt.Errorf("parse RIB: %w", err)
	}

	var routes []Route
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok || len(rm.Addrs) <= syscall.RTAX_NETMASK {
			continue
		}
		dst, ok := rm.Addrs[syscall.RTAX_DST].(*route.Inet4Addr)
		if !ok {
			continue
		}
		ones := 32 // host route without netmask
		if rm.Flags&syscall.RTF_HOST == 0 {
			mask, ok := rm.Addrs[syscall.RTAX_NETMASK].(*route.Inet4Addr)
			if !ok {
				continue
			}
			ones = bits.OnesCount32(uint32(mask.IP[0])<<24 | uint32(mask.IP[1])<<16 | uint32(mask.IP[2])<<8 | uint32(mask.IP[3]))
		}
		routes = append(routes, Route{Dst: netip.PrefixFrom(netip.AddrFrom4(dst.IP), ones), IfIndex: rm.Index})
	}
	return routes, nil
}
