//go:build linux

package capture

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

const readBufferSize = 65536

// packetReader is an AF_PACKET/SOCK_DGRAM socket: the kernel strips the link
// header and delivers IPv4 packets in both directions.
type packetReader struct {
	fd    int
	label string
	// loopbacks holds ifindexes whose outgoing copies duplicate incoming ones.
	loopbacks map[int]bool
}

var _ reader = (*packetReader)(nil)

func open(iface string, port uint16) ([]reader, error) {
	ifindex := 0 // 0 = all interfaces
	label := AllInterfaces
	if !strings.EqualFold(iface, AllInterfaces) {
		ifi, err := net.InterfaceByName(iface)
		if err != nil {
			return nil, fmt.Errorf("lookup interface %q: %w", iface, err)
		}
		ifindex = ifi.Index
		label = ifi.Name
	}

	r, err := openPacketSocket(ifindex, port)
	if err != nil {
		return nil, err
	}
	r.label = label

	ifaces, err := interfacesFor(AllInterfaces)
	if err != nil {
		_ = r.close()
		return nil, err
	}
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagLoopback != 0 {
			r.loopbacks[ifi.Index] = true
		}
	}
	return []reader{r}, nil
}

func openPacketSocket(ifindex int, port uint16) (*packetReader, error) {
	proto := htons(unix.ETH_P_IP)
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, int(proto))
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			return nil, fmt.Errorf("open AF_PACKET socket: %w", ErrPermission)
		}
		return nil, fmt.Errorf("open AF_PACKET socket: %w", err)
	}
	r := &packetReader{fd: fd, loopbacks: make(map[int]bool)}

	prog, err := filterProgram(LinkRaw, port)
	if err != nil {
		_ = r.close()
		return nil, err
	}
	fprog := unix.SockFprog{
		Len:    uint16(len(prog)),                            //nolint:gosec // program length is a small constant
		Filter: (*unix.SockFilter)(unsafe.Pointer(&prog[0])), // bpf.RawInstruction has the same layout
	}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &fprog); err != nil {
		_ = r.close()
		return nil, fmt.Errorf("attach BPF filter: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: proto, Ifindex: ifindex}); err != nil {
		_ = r.close()
		return nil, fmt.Errorf("bind AF_PACKET socket: %w", err)
	}
	tv := unix.NsecToTimeval(pollInterval.Nanoseconds())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		_ = r.close()
		return nil, fmt.Errorf("set receive timeout: %w", err)
	}
	return r, nil
}

func (r *packetReader) read(buf []byte) (Packet, bool, error) {
	n, from, err := unix.Recvfrom(r.fd, buf, 0)
	if err != nil {
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			return Packet{}, false, nil
		}
		return Packet{}, false, err
	}
	if duplicateLoopback(from, r.loopbacks) {
		return Packet{}, false, nil
	}
	pkt, ok := DecodeIPv4UDP(buf[:n])
	return pkt, ok, nil
}

// duplicateLoopback reports whether from is the outgoing copy of a loopback
// packet; AF_PACKET delivers it again as incoming on the same interface.
func duplicateLoopback(from unix.Sockaddr, loopbacks map[int]bool) bool {
	ll, ok := from.(*unix.SockaddrLinklayer)
	return ok && ll.Pkttype == unix.PACKET_OUTGOING && loopbacks[ll.Ifindex]
}

func (r *packetReader) close() error { return unix.Close(r.fd) }
func (r *packetReader) name() string { return r.label }

// htons converts v to network byte order as stored in a native integer.
func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}
