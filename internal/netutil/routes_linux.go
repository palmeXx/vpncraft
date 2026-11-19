//go:build linux

package netutil

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"syscall"
	"unsafe"
)

// Routes dumps IPv4 routes of all routing tables via netlink. Policy-routing
// VPNs (e.g. Tailscale uses table 52) are included this way.
func Routes() ([]Route, error) {
	rib, err := syscall.NetlinkRIB(syscall.RTM_GETROUTE, syscall.AF_INET)
	if err != nil {
		return nil, fmt.Errorf("netlink route dump: %w", err)
	}
	msgs, err := syscall.ParseNetlinkMessage(rib)
	if err != nil {
		return nil, fmt.Errorf("parse netlink messages: %w", err)
	}

	var routes []Route
	for i := range msgs {
		m := &msgs[i]
		if m.Header.Type != syscall.RTM_NEWROUTE || len(m.Data) < syscall.SizeofRtMsg {
			continue
		}
		rtm := (*syscall.RtMsg)(unsafe.Pointer(&m.Data[0]))
		if rtm.Family != syscall.AF_INET || rtm.Dst_len == 0 {
			continue
		}
		attrs, err := syscall.ParseNetlinkRouteAttr(m)
		if err != nil {
			continue
		}
		var (
			dst     netip.Addr
			ifIndex int
		)
		for _, a := range attrs {
			switch a.Attr.Type {
			case syscall.RTA_DST:
				if len(a.Value) == 4 {
					dst = netip.AddrFrom4([4]byte(a.Value))
				}
			case syscall.RTA_OIF:
				if len(a.Value) == 4 {
					ifIndex = int(binary.NativeEndian.Uint32(a.Value))
				}
			}
		}
		if dst.IsValid() && ifIndex > 0 {
			routes = append(routes, Route{Dst: netip.PrefixFrom(dst, int(rtm.Dst_len)), IfIndex: ifIndex})
		}
	}
	return routes, nil
}
