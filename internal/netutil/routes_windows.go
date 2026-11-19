//go:build windows

package netutil

import (
	"fmt"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Routes reads the IPv4 forwarding table via GetIpForwardTable2.
func Routes() ([]Route, error) {
	var table *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_INET, &table); err != nil {
		return nil, fmt.Errorf("GetIpForwardTable2: %w", err)
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))

	var routes []Route
	for _, row := range table.Rows() {
		p := row.DestinationPrefix
		if p.Prefix.Family != windows.AF_INET {
			continue
		}
		// SOCKADDR_IN: family, port, then the IPv4 address in network order.
		addr := *(*[4]byte)(unsafe.Pointer(&p.Prefix.Data[0]))
		routes = append(routes, Route{
			Dst:     netip.PrefixFrom(netip.AddrFrom4(addr), int(p.PrefixLength)),
			IfIndex: int(row.InterfaceIndex),
		})
	}
	return routes, nil
}
