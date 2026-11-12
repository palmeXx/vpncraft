//go:build integration

// Package integration exercises the real binary and OS network stack.
// Tests that need raw sockets are skipped unless run as root/Administrator:
//
//	make test-integration            # unprivileged subset
//	sudo make test-integration       # full suite
package integration

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/palmeXx/vpncraft/internal/capture"
	"github.com/palmeXx/vpncraft/internal/discovery"
	"github.com/palmeXx/vpncraft/internal/relay"
)

const buildinfoPkg = "github.com/palmeXx/vpncraft/internal/buildinfo"

func requirePrivileged(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		t.Skip("requires root (raw sockets)")
	}
}

func loopbackName(t *testing.T) string {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagLoopback != 0 && ifi.Flags&net.FlagUp != 0 {
			return ifi.Name
		}
	}
	t.Skip("no loopback interface")
	return ""
}

// freeUDPPort returns a currently unused UDP port on 127.0.0.1.
func freeUDPPort(t *testing.T) uint16 {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return uint16(c.LocalAddr().(*net.UDPAddr).Port)
}

func TestBinaryInjectsCommit(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "vpncraft")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	ldflags := "-X " + buildinfoPkg + ".Version=v0.0.0-test -X " + buildinfoPkg + ".Commit=deadbeef"
	build := exec.Command("go", "build", "-ldflags", ldflags, "-o", bin, "../../cmd/vpncraft")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	// Isolate from the developer's real config file.
	env := append(os.Environ(), "XDG_CONFIG_HOME="+t.TempDir())
	versionCmd := exec.Command(bin, "-version")
	versionCmd.Env = env
	out, err := versionCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("vpncraft -version: %v\n%s", err, out)
	}
	for _, want := range []string{"vpncraft v0.0.0-test", "commit deadbeef"} {
		if !bytes.Contains(out, []byte(want)) {
			t.Errorf("output %q missing %q", out, want)
		}
	}

	badCmd := exec.Command(bin, "-m", "bogus")
	badCmd.Env = env
	out, _ = badCmd.CombinedOutput()
	if !strings.Contains(string(out), `"bogus" is invalid`) {
		t.Errorf("bad mode output = %q", out)
	}
}

func TestCaptureLoopback(t *testing.T) {
	requirePrivileged(t)
	if runtime.GOOS == "windows" {
		t.Skip("SIO_RCVALL does not support the loopback interface")
	}
	iface := loopbackName(t)
	port := freeUDPPort(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	got := make(chan capture.Packet, 1)
	done := make(chan error, 1)
	go func() {
		done <- capture.Run(ctx, iface, port, func(p capture.Packet) {
			p.Payload = bytes.Clone(p.Payload)
			select {
			case got <- p:
			default:
			}
		})
	}()

	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	payload := []byte{0xF7, 0x2F, 0x10, 0x00, 'P', 'X', '3', 'W'}
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case p := <-got:
			if !bytes.Equal(p.Payload, payload) {
				t.Errorf("payload = %x, want %x", p.Payload, payload)
			}
			if p.Dst.Port() != port {
				t.Errorf("dst port = %d, want %d", p.Dst.Port(), port)
			}
			cancel()
			if err := <-done; err != nil {
				t.Errorf("capture.Run() error = %v", err)
			}
			return
		case err := <-done:
			t.Fatalf("capture.Run() returned early: %v", err)
		case <-tick.C:
			// Capture start-up is asynchronous; resend until seen.
			if _, err := conn.Write(payload); err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal("timed out waiting for captured packet")
		}
	}
}

func TestRawForwarderSourcePort(t *testing.T) {
	requirePrivileged(t)

	ln, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	dst := ln.LocalAddr().(*net.UDPAddr).AddrPort()

	const srcPort = 6112
	fwd, err := relay.NewRawForwarder(srcPort)
	if err != nil {
		t.Fatalf("NewRawForwarder() error = %v", err)
	}
	defer fwd.Close()

	payload := []byte{0xF7, 0x30, 0x08, 0x00, 1, 2, 3, 4}
	if err := fwd.Forward(payload, dst); err != nil {
		t.Fatalf("Forward() error = %v", err)
	}

	if err := ln.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1500)
	n, from, err := ln.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatalf("read forwarded datagram: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Errorf("payload = %x, want %x", buf[:n], payload)
	}
	if from.Port() != srcPort {
		t.Errorf("source port = %d, want %d", from.Port(), srcPort)
	}
}

func TestSweepLoopback(t *testing.T) {
	requirePrivileged(t)

	conn, err := discovery.Listen()
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer conn.Close()

	targets := []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	got, err := discovery.Sweep(context.Background(), conn, targets, discovery.Options{Timeout: time.Second})
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("Sweep() error = %v", err)
	}
	if len(got) != 1 || got[0] != targets[0] {
		t.Errorf("Sweep() = %v, want %v", got, targets)
	}
}
