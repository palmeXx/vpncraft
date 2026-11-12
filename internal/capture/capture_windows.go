//go:build windows

package capture

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	readBufferSize = 65536
	// sioRcvAll is SIO_RCVALL (_WSAIOW(IOC_VENDOR, 1)); not exported by x/sys/windows.
	sioRcvAll = windows.IOC_IN | windows.IOC_VENDOR | 1
	rcvAllOn  = 1
)

// rawReader is an IPPROTO_IP raw socket in SIO_RCVALL mode bound to one local
// IPv4 address. Windows delivers whole IPv4 packets without link header.
type rawReader struct {
	fd    windows.Handle
	label string
}

func open(iface string, port uint16) ([]reader, error) {
	_ = port // SIO_RCVALL has no kernel filter; Run filters by port in user space.

	ifaces, err := interfacesFor(iface)
	if err != nil {
		return nil, err
	}
	all := strings.EqualFold(iface, AllInterfaces)

	var (
		readers []reader
		errs    []error
	)
	for _, ifi := range ifaces {
		if all && ifi.Flags&net.FlagLoopback != 0 {
			continue // SIO_RCVALL is not supported on the loopback pseudo-interface
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			errs = append(errs, fmt.Errorf("list addresses of %q: %w", ifi.Name, err))
			continue
		}
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok || ipNet.IP.To4() == nil {
				continue
			}
			r, err := openRaw(ipNet.IP.To4(), ifi.Name)
			if err != nil {
				if !all || errors.Is(err, ErrPermission) {
					closeAll(readers)
					return nil, err
				}
				errs = append(errs, err)
				continue
			}
			readers = append(readers, r)
		}
	}
	if len(readers) == 0 {
		if len(errs) == 0 {
			return nil, fmt.Errorf("no IPv4 address on %q", iface)
		}
		return nil, errors.Join(errs...)
	}
	return readers, nil
}

func openRaw(ip net.IP, ifName string) (*rawReader, error) {
	label := fmt.Sprintf("%s (%s)", ifName, ip)
	fd, err := windows.Socket(windows.AF_INET, windows.SOCK_RAW, windows.IPPROTO_IP)
	if err != nil {
		if errors.Is(err, windows.WSAEACCES) {
			return nil, fmt.Errorf("open raw socket on %s: %w", label, ErrPermission)
		}
		return nil, fmt.Errorf("open raw socket on %s: %w", label, err)
	}
	r := &rawReader{fd: fd, label: label}

	sa := &windows.SockaddrInet4{}
	copy(sa.Addr[:], ip)
	if err := windows.Bind(fd, sa); err != nil {
		_ = r.close()
		return nil, fmt.Errorf("bind raw socket on %s: %w", label, err)
	}

	in := uint32(rcvAllOn)
	var ret uint32
	if err := windows.WSAIoctl(fd, sioRcvAll, (*byte)(unsafe.Pointer(&in)), uint32(unsafe.Sizeof(in)), nil, 0, &ret, nil, 0); err != nil {
		_ = r.close()
		if errors.Is(err, windows.WSAEACCES) {
			return nil, fmt.Errorf("enable SIO_RCVALL on %s: %w", label, ErrPermission)
		}
		return nil, fmt.Errorf("enable SIO_RCVALL on %s: %w", label, err)
	}

	if err := windows.SetsockoptInt(fd, windows.SOL_SOCKET, windows.SO_RCVTIMEO, int(pollInterval.Milliseconds())); err != nil {
		_ = r.close()
		return nil, fmt.Errorf("set receive timeout on %s: %w", label, err)
	}
	return r, nil
}

func (r *rawReader) read(buf []byte) (Packet, bool, error) {
	n, _, err := windows.Recvfrom(r.fd, buf, 0)
	if err != nil {
		if errors.Is(err, windows.WSAETIMEDOUT) || errors.Is(err, windows.WSAEMSGSIZE) {
			return Packet{}, false, nil
		}
		return Packet{}, false, err
	}
	pkt, ok := DecodeIPv4UDP(buf[:n])
	return pkt, ok, nil
}

func (r *rawReader) close() error { return windows.Closesocket(r.fd) }
func (r *rawReader) name() string { return r.label }

func closeAll(rs []reader) {
	for _, r := range rs {
		_ = r.close()
	}
}
