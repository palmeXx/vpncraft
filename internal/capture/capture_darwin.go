//go:build darwin

package capture

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	readBufferSize = 65536
	maxBPFDevices  = 256
	bpfAlignment   = 4 // BPF_ALIGNMENT == sizeof(int32_t) on Darwin
	ifNameSize     = unix.IFNAMSIZ
	ifreqSize      = 32
)

// bpfReader reads from a /dev/bpf device bound to one interface. A single
// read(2) may return several frames, which are buffered in pending.
type bpfReader struct {
	fd      int
	iface   string
	link    LinkType
	buf     []byte
	pending []byte
}

var _ reader = (*bpfReader)(nil)

func open(iface string, port uint16) ([]reader, error) {
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
		r, err := openBPF(ifi.Name, port)
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
	if len(readers) == 0 {
		return nil, errors.Join(errs...)
	}
	return readers, nil
}

func openBPF(iface string, port uint16) (*bpfReader, error) {
	fd, err := openBPFDevice()
	if err != nil {
		return nil, err
	}
	r := &bpfReader{fd: fd, iface: iface}

	if err := r.configure(port); err != nil {
		_ = r.close()
		return nil, fmt.Errorf("bpf on %s: %w", iface, err)
	}
	return r, nil
}

func openBPFDevice() (int, error) {
	for i := range maxBPFDevices {
		fd, err := unix.Open(fmt.Sprintf("/dev/bpf%d", i), unix.O_RDONLY|unix.O_CLOEXEC, 0)
		switch {
		case err == nil:
			return fd, nil
		case errors.Is(err, unix.EBUSY):
			continue
		case errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM):
			return -1, fmt.Errorf("open /dev/bpf%d: %w", i, ErrPermission)
		default:
			return -1, fmt.Errorf("open /dev/bpf%d: %w", i, err)
		}
	}
	return -1, errors.New("no free /dev/bpf device")
}

func (r *bpfReader) configure(port uint16) error {
	// Buffer size must be set before binding the interface.
	if err := unix.IoctlSetPointerInt(r.fd, unix.BIOCSBLEN, readBufferSize); err != nil {
		return fmt.Errorf("BIOCSBLEN: %w", err)
	}

	var ifr [ifreqSize]byte
	if len(r.iface) >= ifNameSize {
		return fmt.Errorf("interface name %q too long", r.iface)
	}
	copy(ifr[:], r.iface)
	if err := ioctlPtr(r.fd, unix.BIOCSETIF, unsafe.Pointer(&ifr)); err != nil {
		return fmt.Errorf("BIOCSETIF: %w", err)
	}

	blen, err := unix.IoctlGetInt(r.fd, unix.BIOCGBLEN)
	if err != nil {
		return fmt.Errorf("BIOCGBLEN: %w", err)
	}
	r.buf = make([]byte, blen)

	if err := unix.IoctlSetPointerInt(r.fd, unix.BIOCIMMEDIATE, 1); err != nil {
		return fmt.Errorf("BIOCIMMEDIATE: %w", err)
	}
	tv := unix.NsecToTimeval(pollInterval.Nanoseconds())
	if err := ioctlPtr(r.fd, unix.BIOCSRTIMEOUT, unsafe.Pointer(&tv)); err != nil {
		return fmt.Errorf("BIOCSRTIMEOUT: %w", err)
	}

	dlt, err := unix.IoctlGetInt(r.fd, unix.BIOCGDLT)
	if err != nil {
		return fmt.Errorf("BIOCGDLT: %w", err)
	}
	r.link = LinkType(dlt)

	prog, err := filterProgram(r.link, port)
	if err != nil {
		return err
	}
	bp := unix.BpfProgram{
		Len:   uint32(len(prog)),                         //nolint:gosec // program length is a small constant
		Insns: (*unix.BpfInsn)(unsafe.Pointer(&prog[0])), // bpf.RawInstruction has the same layout
	}
	if err := ioctlPtr(r.fd, unix.BIOCSETF, unsafe.Pointer(&bp)); err != nil {
		return fmt.Errorf("BIOCSETF: %w", err)
	}
	return nil
}

func (r *bpfReader) read([]byte) (Packet, bool, error) {
	if len(r.pending) < unix.SizeofBpfHdr {
		n, err := unix.Read(r.fd, r.buf)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				return Packet{}, false, nil
			}
			return Packet{}, false, err
		}
		r.pending = r.buf[:n]
		if n < unix.SizeofBpfHdr {
			r.pending = nil
			return Packet{}, false, nil
		}
	}

	frame, rest, ok := nextBPFFrame(r.pending)
	r.pending = rest
	if !ok {
		return Packet{}, false, nil
	}
	pkt, ok := DecodeFrame(r.link, frame)
	return pkt, ok, nil
}

// nextBPFFrame splits the first captured frame off a BPF read buffer.
func nextBPFFrame(b []byte) (frame, rest []byte, ok bool) {
	if len(b) < unix.SizeofBpfHdr {
		return nil, nil, false
	}
	caplen := int(binary.NativeEndian.Uint32(b[8:12]))
	hdrlen := int(binary.NativeEndian.Uint16(b[16:18]))
	end := hdrlen + caplen
	if hdrlen < unix.SizeofBpfHdr || end > len(b) {
		return nil, nil, false
	}
	next := min((end+bpfAlignment-1)&^(bpfAlignment-1), len(b))
	return b[hdrlen:end], b[next:], true
}

func (r *bpfReader) close() error { return unix.Close(r.fd) }
func (r *bpfReader) name() string { return r.iface }

func closeAll(rs []reader) {
	for _, r := range rs {
		_ = r.close()
	}
}

// ioctlPtr issues an ioctl with a struct argument; x/sys/unix exports no
// generic pointer variant for Darwin.
func ioctlPtr(fd int, req uint, arg unsafe.Pointer) error {
	//nolint:staticcheck // SYS_IOCTL is routed through libSystem's syscall(2) trampoline.
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(arg))
	if errno != 0 {
		return errno
	}
	return nil
}
