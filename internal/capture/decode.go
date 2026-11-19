package capture

import (
	"encoding/binary"
	"net/netip"
)

// LinkType identifies the framing in front of the IPv4 header.
type LinkType int

// Supported link types (values follow libpcap DLT_* numbering).
const (
	LinkNull     LinkType = 0   // 4-byte host-order address family (BSD loopback, utun)
	LinkEthernet LinkType = 1   // Ethernet II, optional single 802.1Q tag
	LinkRaw      LinkType = 12  // bare IP
	LinkLoop     LinkType = 108 // 4-byte network-order address family (OpenBSD loopback)
)

const (
	etherTypeIPv4 = 0x0800
	etherTypeVLAN = 0x8100
	afInet        = 2

	ipv4MinHeader = 20
	udpHeader     = 8
	protoUDP      = 17
)

// Packet is a decoded IPv4/UDP datagram. Payload aliases the read buffer
// unless copied by the caller.
type Packet struct {
	Src     netip.AddrPort
	Dst     netip.AddrPort
	Payload []byte
}

// DecodeFrame strips the link-layer header and decodes the IPv4/UDP datagram.
func DecodeFrame(link LinkType, frame []byte) (Packet, bool) {
	switch link {
	case LinkRaw:
		return DecodeIPv4UDP(frame)
	case LinkNull, LinkLoop:
		if len(frame) < 4 {
			return Packet{}, false
		}
		// Family is host-order for DLT_NULL; accept both orders for AF_INET.
		if binary.LittleEndian.Uint32(frame) != afInet && binary.BigEndian.Uint32(frame) != afInet {
			return Packet{}, false
		}
		return DecodeIPv4UDP(frame[4:])
	case LinkEthernet:
		if len(frame) < 14 {
			return Packet{}, false
		}
		off := 12
		etherType := binary.BigEndian.Uint16(frame[off:])
		if etherType == etherTypeVLAN {
			off += 4
			if len(frame) < off+2 {
				return Packet{}, false
			}
			etherType = binary.BigEndian.Uint16(frame[off:])
		}
		if etherType != etherTypeIPv4 {
			return Packet{}, false
		}
		return DecodeIPv4UDP(frame[off+2:])
	default:
		return Packet{}, false
	}
}

// DecodeIPv4UDP decodes an IPv4 packet carrying UDP. Non-first fragments are
// rejected; a first fragment yields the payload bytes that are present.
func DecodeIPv4UDP(b []byte) (Packet, bool) {
	if len(b) < ipv4MinHeader || b[0]>>4 != 4 {
		return Packet{}, false
	}
	ihl := int(b[0]&0x0f) * 4
	totalLen := int(binary.BigEndian.Uint16(b[2:4]))
	fragOffset := binary.BigEndian.Uint16(b[6:8]) & 0x1fff
	if ihl < ipv4MinHeader || b[9] != protoUDP || fragOffset != 0 {
		return Packet{}, false
	}
	// Some capture paths (e.g. TSO, Windows raw sockets) report 0 or a
	// mismatching total length; trust the captured length then.
	if totalLen < ihl+udpHeader || totalLen > len(b) {
		totalLen = len(b)
	}
	if totalLen < ihl+udpHeader {
		return Packet{}, false
	}

	udp := b[ihl:totalLen]
	end := int(binary.BigEndian.Uint16(udp[4:6]))
	if end < udpHeader || end > len(udp) {
		end = len(udp)
	}

	src, _ := netip.AddrFromSlice(b[12:16])
	dst, _ := netip.AddrFromSlice(b[16:20])
	return Packet{
		Src:     netip.AddrPortFrom(src, binary.BigEndian.Uint16(udp[0:2])),
		Dst:     netip.AddrPortFrom(dst, binary.BigEndian.Uint16(udp[2:4])),
		Payload: udp[udpHeader:end],
	}, true
}
