package tui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/palmeXx/vpncraft/internal/app"
	"github.com/palmeXx/vpncraft/internal/capture"
	"github.com/palmeXx/vpncraft/internal/netutil"
	"github.com/palmeXx/vpncraft/internal/settings"
)

func addrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParseAddr(s)
	}
	return out
}

var testNICs = []netutil.NIC{
	{Name: "wt0", Up: true, VPN: true, VPNReason: "name", Addrs: []netip.Prefix{netip.MustParsePrefix("100.88.1.2/16")}},
	{Name: "en0", Up: true, Addrs: []netip.Prefix{netip.MustParsePrefix("192.168.1.2/24")}},
	{Name: "lo0", Up: true, Loopback: true, Addrs: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/8")}},
	{Name: "awdl0", Up: true},
}

type fakes struct {
	scanResult []netip.Addr
	scanErr    error
	runErr     error
	runLines   []string
	runBlocks  bool
	savedPath  string
	savedCfg   settings.Config
	ranCfg     settings.Config
	names      map[netip.Addr]string
}

func (f *fakes) deps() Deps {
	return Deps{
		ListNICs: func() ([]netutil.NIC, error) { return slices.Clone(testNICs), nil },
		ScanOptions: func(iface string, _ settings.Scan) (netip.Addr, []app.ScanOption, int, error) {
			if iface != "wt0" {
				return netip.Addr{}, nil, 0, fmt.Errorf("%q: no IPv4 address on interface", iface)
			}
			return netip.MustParseAddr("100.88.1.2"), []app.ScanOption{
				{Prefix: netip.MustParsePrefix("100.64.0.0/10"), Label: "detected (routing table)", Detected: true},
				{Prefix: netip.MustParsePrefix("100.88.0.0/29"), Label: "small test range", Allowed: true},
				{Prefix: netip.MustParsePrefix("100.88.0.0/30"), Label: "tiny test range", Allowed: true},
			}, 1, nil
		},
		Scan: func(_ context.Context, t app.ScanTarget, _ settings.Scan, progress func(app.Progress)) ([]netip.Addr, error) {
			progress(app.Progress{Sent: len(t.Hosts), Total: len(t.Hosts), Alive: len(f.scanResult)})
			return f.scanResult, f.scanErr
		},
		Run: func(ctx context.Context, cfg settings.Config, out io.Writer) error {
			f.ranCfg = cfg
			for _, l := range f.runLines {
				_, _ = io.WriteString(out, l+"\n")
			}
			if f.runBlocks {
				<-ctx.Done()
			}
			return f.runErr
		},
		LookupNames: func(_ context.Context, as []netip.Addr) map[netip.Addr]string {
			out := map[netip.Addr]string{}
			for _, a := range as {
				if name, ok := f.names[a]; ok {
					out[a] = name
				}
			}
			return out
		},
		Save: func(path string, cfg settings.Config) error {
			f.savedPath, f.savedCfg = path, cfg
			return nil
		},
	}
}

func key(k string) tea.KeyPressMsg {
	switch k {
	case "enter":
		return tea.KeyPressMsg{Code: tea.KeyEnter}
	case "esc":
		return tea.KeyPressMsg{Code: tea.KeyEscape}
	case "space":
		return tea.KeyPressMsg{Code: tea.KeySpace, Text: " "}
	case "down":
		return tea.KeyPressMsg{Code: tea.KeyDown}
	case "up":
		return tea.KeyPressMsg{Code: tea.KeyUp}
	case "tab":
		return tea.KeyPressMsg{Code: tea.KeyTab}
	case "ctrl+c":
		return tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl}
	}
	r := []rune(k)[0]
	return tea.KeyPressMsg{Code: r, Text: k}
}

// press sends keys and returns the model plus the last command.
func press(t *testing.T, m Model, keys ...string) (Model, tea.Cmd) {
	t.Helper()
	var cmd tea.Cmd
	for _, k := range keys {
		var next tea.Model
		next, cmd = m.Update(key(k))
		m = next.(Model)
	}
	return m, cmd
}

// drain executes cmd and feeds resulting messages back until the background
// operation reports completion.
func drain(t *testing.T, m Model, cmd tea.Cmd) Model {
	t.Helper()
	for range 100 {
		if cmd == nil {
			return m
		}
		msg := cmd()
		if msg == nil {
			return m
		}
		var next tea.Model
		next, cmd = m.Update(msg)
		m = next.(Model)
		switch msg.(type) {
		case runDoneMsg, savedMsg, nicsMsg, namesMsg:
			return m
		case scanDoneMsg:
			return drain(t, m, cmd) // follow-up name lookup
		}
	}
	t.Fatal("background operation did not finish")
	return m
}

func newModel(t *testing.T, f *fakes, cfg settings.Config) Model {
	t.Helper()
	m := New(cfg, "/home/test/.config/vpncraft/config.yaml", f.deps())
	m = drain(t, m, m.loadNICs)
	return drain(t, m, m.resolveNames(m.cfg.Peers))
}

func TestNICSelection(t *testing.T) {
	f := &fakes{}
	cfg := settings.Default()
	cfg.Interface = "en0"
	m := newModel(t, f, cfg)

	if m.screen != screenNICs || len(m.nics) != 3 || len(m.allNICs) != 4 {
		t.Fatalf("screen = %v, nics = %d", m.screen, len(m.nics))
	}
	if m.nicCursor != 1 {
		t.Errorf("cursor = %d, want configured en0 (1)", m.nicCursor)
	}
	view := m.View().Content
	if !strings.Contains(view, "VPN") || !strings.Contains(view, "wt0") {
		t.Errorf("NIC view misses VPN highlight:\n%s", view)
	}

	m, _ = press(t, m, "up", "up", "enter")
	if m.screen != screenMain || m.cfg.Interface != "wt0" {
		t.Errorf("after select: screen = %v, interface = %q", m.screen, m.cfg.Interface)
	}

	m, _ = press(t, m, "esc", "down", "down", "down", "enter")
	if m.cfg.Interface != "lo0" {
		t.Errorf("cursor not clamped: interface = %q", m.cfg.Interface)
	}

	// Interfaces without IPv4 are hidden until toggled with h.
	m, _ = press(t, m, "esc", "h")
	if len(m.nics) != 4 || m.nics[m.nicCursor].Name != "lo0" {
		t.Fatalf("after h: nics = %d, cursor on %q", len(m.nics), m.nics[m.nicCursor].Name)
	}
	m, _ = press(t, m, "down", "enter")
	if m.cfg.Interface != "awdl0" {
		t.Errorf("interface = %q, want awdl0", m.cfg.Interface)
	}
	m, _ = press(t, m, "esc", "h")
	if len(m.nics) != 4 {
		t.Errorf("configured interface must stay visible, nics = %d", len(m.nics))
	}
}

func TestModeToggle(t *testing.T) {
	m := newModel(t, &fakes{}, settings.Default())
	m, _ = press(t, m, "enter")
	if m.cfg.Mode != settings.ModeSniff {
		t.Fatalf("mode = %q", m.cfg.Mode)
	}
	m, _ = press(t, m, "m")
	if m.cfg.Mode != settings.ModeRelay {
		t.Errorf("after m: mode = %q", m.cfg.Mode)
	}
	m, _ = press(t, m, "tab")
	if m.cfg.Mode != settings.ModeSniff {
		t.Errorf("after tab: mode = %q", m.cfg.Mode)
	}
}

func TestScanSelectAndApply(t *testing.T) {
	f := &fakes{scanResult: addrs("100.88.0.5", "100.88.0.7", "100.88.0.9")}
	cfg := settings.Default()
	cfg.Peers = addrs("100.88.0.9", "100.88.0.200")
	m := newModel(t, f, cfg)

	m, cmd := press(t, m, "enter", "s", "enter")
	if m.screen != screenScan || !m.busy {
		t.Fatalf("scan not started: screen = %v, busy = %v, status = %q", m.screen, m.busy, m.status)
	}
	m = drain(t, m, cmd)
	if m.busy || len(m.scanResults) != 3 {
		t.Fatalf("scan not finished: busy = %v, results = %v", m.busy, m.scanResults)
	}
	if m.scanProgress.Sent != 6 || m.scanProgress.Total != 6 {
		t.Errorf("progress not applied: %+v", m.scanProgress)
	}
	// Existing member .9 is pre-checked.
	if !m.scanChecked[netip.MustParseAddr("100.88.0.9")] || m.scanChecked[netip.MustParseAddr("100.88.0.5")] {
		t.Errorf("unexpected pre-selection: %v", m.scanChecked)
	}

	// Check .5, leave .7, uncheck .9.
	m, _ = press(t, m, "space", "down", "down", "space", "enter")
	if m.screen != screenMain {
		t.Fatalf("screen = %v after apply", m.screen)
	}
	if want := addrs("100.88.0.5", "100.88.0.200"); !slices.Equal(m.cfg.Peers, want) {
		t.Errorf("peers = %v, want %v", m.cfg.Peers, want)
	}
}

func TestScanSelectAllAndDiscard(t *testing.T) {
	f := &fakes{scanResult: addrs("100.88.0.5", "100.88.0.7")}
	m := newModel(t, f, settings.Default())
	m, cmd := press(t, m, "enter", "s", "enter")
	m = drain(t, m, cmd)

	m, _ = press(t, m, "a")
	if !m.allChecked() {
		t.Fatal("a did not select all")
	}
	m, _ = press(t, m, "esc")
	if m.screen != screenMain || len(m.cfg.Peers) != 0 {
		t.Errorf("discard changed group: screen = %v, peers = %v", m.screen, m.cfg.Peers)
	}

	m, cmd = press(t, m, "s", "enter")
	m = drain(t, m, cmd)
	m, _ = press(t, m, "a", "a", "enter")
	if len(m.cfg.Peers) != 0 {
		t.Errorf("a twice should deselect all, peers = %v", m.cfg.Peers)
	}
}

func TestScanErrors(t *testing.T) {
	f := &fakes{scanErr: fmt.Errorf("open ICMP socket: %w", capture.ErrPermission)}
	m := newModel(t, f, settings.Default())

	m, cmd := press(t, m, "enter", "s", "enter")
	m = drain(t, m, cmd)
	if !m.statusErr || !strings.Contains(m.status, "sudo") {
		t.Errorf("status = %q, want permission hint", m.status)
	}

	// Interface without IPv4 cannot be scanned.
	m, _ = press(t, m, "esc", "esc", "down", "enter", "s")
	if m.screen != screenMain || !m.statusErr {
		t.Errorf("expected plan error on en0: screen = %v, status = %q", m.screen, m.status)
	}
}

func TestScanCancelIgnoresLateResult(t *testing.T) {
	f := &fakes{scanResult: addrs("100.88.0.5")}
	m := newModel(t, f, settings.Default())
	m, cmd := press(t, m, "enter", "s", "enter")
	m, _ = press(t, m, "esc")
	if m.screen != screenMain || m.busy {
		t.Fatalf("cancel: screen = %v, busy = %v", m.screen, m.busy)
	}
	m = drain(t, m, cmd) // late messages of the cancelled scan
	if m.screen != screenMain || len(m.scanResults) != 0 {
		t.Errorf("late scan result was applied: screen = %v, results = %v", m.screen, m.scanResults)
	}
}

func TestAddAndRemovePeer(t *testing.T) {
	m := newModel(t, &fakes{}, settings.Default())
	m, _ = press(t, m, "enter", "a")
	if m.inputMode != inputPeer {
		t.Fatal("a did not open input")
	}
	m, _ = press(t, m, "n", "o", "enter")
	if !m.statusErr || m.inputMode != inputPeer {
		t.Errorf("invalid address accepted: status = %q", m.status)
	}

	m.input.SetValue("100.64.0.3")
	m, _ = press(t, m, "enter")
	m, _ = press(t, m, "a")
	m.input.SetValue("100.64.0.2")
	m, _ = press(t, m, "enter")
	if want := addrs("100.64.0.2", "100.64.0.3"); !slices.Equal(m.cfg.Peers, want) {
		t.Fatalf("peers = %v, want %v", m.cfg.Peers, want)
	}

	m, _ = press(t, m, "down", "d")
	if want := addrs("100.64.0.2"); !slices.Equal(m.cfg.Peers, want) || m.peerCursor != 0 {
		t.Errorf("after remove: peers = %v, cursor = %d", m.cfg.Peers, m.peerCursor)
	}
	m, _ = press(t, m, "d", "d")
	if len(m.cfg.Peers) != 0 {
		t.Errorf("peers = %v, want empty", m.cfg.Peers)
	}
}

func TestSave(t *testing.T) {
	f := &fakes{}
	cfg := settings.Default()
	cfg.Peers = addrs("100.64.0.2")
	m := newModel(t, f, cfg)

	m, cmd := press(t, m, "enter", "m", "w")
	m = drain(t, m, cmd)
	if f.savedPath != "/home/test/.config/vpncraft/config.yaml" {
		t.Errorf("saved to %q", f.savedPath)
	}
	if f.savedCfg.Interface != "wt0" || f.savedCfg.Mode != settings.ModeRelay || !slices.Equal(f.savedCfg.Peers, cfg.Peers) {
		t.Errorf("saved cfg = %+v", f.savedCfg)
	}
	if m.statusErr || !strings.Contains(m.status, "saved") {
		t.Errorf("status = %q", m.status)
	}
}

func TestRunStreamsOutputAndStops(t *testing.T) {
	f := &fakes{runLines: []string{"[*] WC3 Tool Started in [RELAY] Mode", "[+] forwarded"}, runBlocks: true}
	cfg := settings.Default()
	cfg.Mode = settings.ModeRelay
	cfg.Peers = addrs("100.64.0.2")
	m := newModel(t, f, cfg)

	m, cmd := press(t, m, "enter", "enter")
	if m.screen != screenRun || !m.busy {
		t.Fatalf("run not started: screen = %v", m.screen)
	}
	// Two log lines arrive before the run blocks.
	for range 2 {
		next, c := m.Update(cmd())
		m, cmd = next.(Model), c
	}
	if len(m.logLines) != 2 || !strings.Contains(m.View().Content, "[+] forwarded") {
		t.Fatalf("log lines = %v", m.logLines)
	}
	if f.ranCfg.Scan.Enabled || f.ranCfg.Interface != "wt0" || !slices.Equal(f.ranCfg.Peers, cfg.Peers) {
		t.Errorf("run cfg = %+v", f.ranCfg)
	}

	m, _ = press(t, m, "esc")
	if !m.stopReq {
		t.Fatal("esc did not request stop")
	}
	m = drain(t, m, cmd)
	if m.screen != screenMain || m.busy {
		t.Errorf("after stop: screen = %v, busy = %v, status = %q", m.screen, m.busy, m.status)
	}
}

func TestRunErrorStaysOnRunScreen(t *testing.T) {
	f := &fakes{runErr: fmt.Errorf("capture: %w", capture.ErrPermission)}
	m := newModel(t, f, settings.Default())
	m, cmd := press(t, m, "enter", "enter")
	m = drain(t, m, cmd)
	if m.screen != screenRun || m.busy || !errors.Is(m.runErr, capture.ErrPermission) {
		t.Fatalf("screen = %v, busy = %v, err = %v", m.screen, m.busy, m.runErr)
	}
	if !strings.Contains(m.status, "sudo") || !strings.Contains(m.View().Content, "failed") {
		t.Errorf("status = %q", m.status)
	}
	m, _ = press(t, m, "esc")
	if m.screen != screenMain {
		t.Errorf("esc after failure: screen = %v", m.screen)
	}
}

func TestQuit(t *testing.T) {
	m := newModel(t, &fakes{}, settings.Default())
	_, cmd := press(t, m, "ctrl+c")
	if cmd == nil {
		t.Fatal("ctrl+c returned no command")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Error("ctrl+c did not quit")
	}
}

func TestViewsRender(t *testing.T) {
	f := &fakes{scanResult: addrs("100.88.0.5")}
	m := newModel(t, f, settings.Default())
	next, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 12})
	m = next.(Model)

	for _, step := range []struct {
		keys []string
		want string
	}{
		{nil, "Select network interface"},
		{[]string{"enter"}, "Peer group (0)"},
		{[]string{"a"}, "Peer IPv4"},
		{[]string{"esc", "s"}, "Select scan range"},
		{[]string{"enter"}, "Ping scan 100.88.0.0/29"},
	} {
		var cmd tea.Cmd
		m, cmd = press(t, m, step.keys...)
		if m.screen == screenScan {
			m = drain(t, m, cmd)
		}
		if v := m.View(); !strings.Contains(v.Content, step.want) || !v.AltScreen {
			t.Errorf("after %v view misses %q:\n%s", step.keys, step.want, v.Content)
		}
	}
}

func TestLineWriter(t *testing.T) {
	ch := make(chan tea.Msg, 10)
	w := &lineWriter{ctx: context.Background(), gen: 7, ch: ch}
	_, _ = io.WriteString(w, "a\nb")
	_, _ = io.WriteString(w, "c\r\rd\n")
	close(ch)
	var got []string
	for msg := range ch {
		l := msg.(logLineMsg)
		if l.gen != 7 {
			t.Errorf("gen = %d", l.gen)
		}
		got = append(got, l.line)
	}
	if want := []string{"a", "bc", "d"}; !slices.Equal(got, want) {
		t.Errorf("lines = %q, want %q", got, want)
	}
}

func TestWindow(t *testing.T) {
	tests := []struct{ cur, n, h, start, end int }{
		{0, 5, 10, 0, 5},
		{0, 20, 5, 0, 5},
		{10, 20, 5, 8, 13},
		{19, 20, 5, 15, 20},
		{3, 20, 0, 0, 20},
	}
	for _, tt := range tests {
		if s, e := window(tt.cur, tt.n, tt.h); s != tt.start || e != tt.end {
			t.Errorf("window(%d,%d,%d) = %d,%d; want %d,%d", tt.cur, tt.n, tt.h, s, e, tt.start, tt.end)
		}
	}
}

func TestHostnames(t *testing.T) {
	f := &fakes{
		scanResult: addrs("100.88.0.5", "100.88.0.7"),
		names: map[netip.Addr]string{
			netip.MustParseAddr("100.64.0.2"): "bob-laptop",
			netip.MustParseAddr("100.88.0.5"): "carol-pc",
		},
	}
	cfg := settings.Default()
	cfg.Peers = addrs("100.64.0.2")
	m := newModel(t, f, cfg)
	m, _ = press(t, m, "enter")
	if !strings.Contains(m.View().Content, "bob-laptop") {
		t.Errorf("peer group misses host name:\n%s", m.View().Content)
	}

	m, cmd := press(t, m, "s", "enter")
	m = drain(t, m, cmd)
	view := m.View().Content
	if !strings.Contains(view, "carol-pc") || !strings.Contains(view, "network from small test range") {
		t.Errorf("scan view misses host name or source:\n%s", view)
	}
	if name, ok := m.names[netip.MustParseAddr("100.88.0.7")]; !ok || name != "" {
		t.Errorf("unresolved address not cached as empty: %q, %v", name, ok)
	}
	if cmd := m.resolveNames(m.scanResults); cmd != nil {
		t.Error("cached addresses are looked up again")
	}
}

func TestScanRangeSelection(t *testing.T) {
	m := newModel(t, &fakes{}, settings.Default())
	m, _ = press(t, m, "enter", "s")
	if m.screen != screenRange || m.rangeCursor != 1 {
		t.Fatalf("screen = %v, cursor = %d; want range screen on first allowed option", m.screen, m.rangeCursor)
	}
	view := m.View().Content
	if !strings.Contains(view, "100.64.0.0/10") || !strings.Contains(view, "too large") || !strings.Contains(view, "4194302 hosts") {
		t.Errorf("range view:\n%s", view)
	}

	// The detected /10 cannot be selected.
	m, _ = press(t, m, "up", "enter")
	if m.screen != screenRange || !m.statusErr || !strings.Contains(m.status, "too large") {
		t.Fatalf("disallowed range: screen = %v, status = %q", m.screen, m.status)
	}

	// Choosing a standard range remembers it as scan.network.
	m, cmd := press(t, m, "down", "down", "enter")
	m = drain(t, m, cmd)
	if m.scanTarget.Prefix != netip.MustParsePrefix("100.88.0.0/30") || m.cfg.Scan.Network != m.scanTarget.Prefix {
		t.Errorf("target = %s, scan.network = %s", m.scanTarget.Prefix, m.cfg.Scan.Network)
	}
}

func TestScanRangeCustom(t *testing.T) {
	m := newModel(t, &fakes{}, settings.Default())
	m, _ = press(t, m, "enter", "s", "c")
	if m.inputMode != inputRange || !strings.Contains(m.View().Content, "Scan range (CIDR)") {
		t.Fatalf("custom input not open: mode = %v", m.inputMode)
	}
	for _, bad := range []string{"nope", "100.64.0.0/10", "2001:db8::/120"} {
		m.input.SetValue(bad)
		m, _ = press(t, m, "enter")
		if !m.statusErr || m.inputMode != inputRange {
			t.Errorf("%q accepted: status = %q", bad, m.status)
		}
	}
	m.input.SetValue("192.0.2.9/30")
	m, cmd := press(t, m, "enter")
	m = drain(t, m, cmd)
	want := netip.MustParsePrefix("192.0.2.8/30")
	if m.screen != screenScan || m.scanTarget.Prefix != want || m.scanTarget.Source != "custom" || m.cfg.Scan.Network != want {
		t.Errorf("screen = %v, target = %+v, scan.network = %s", m.screen, m.scanTarget, m.cfg.Scan.Network)
	}

	m, _ = press(t, m, "esc", "s", "esc")
	if m.screen != screenMain {
		t.Errorf("esc on range screen: screen = %v", m.screen)
	}
}

func TestScanRangeDetectedClearsNetwork(t *testing.T) {
	cfg := settings.Default()
	cfg.Scan.Network = netip.MustParsePrefix("10.0.0.0/24")
	m := newModel(t, &fakes{}, cfg)
	m.deps.ScanOptions = func(string, settings.Scan) (netip.Addr, []app.ScanOption, int, error) {
		return netip.MustParseAddr("10.8.0.2"), []app.ScanOption{
			{Prefix: netip.MustParsePrefix("10.8.0.0/29"), Label: "detected (interface mask)", Detected: true, Allowed: true},
		}, 0, nil
	}
	m, cmd := press(t, m, "enter", "s", "enter")
	m = drain(t, m, cmd)
	if m.cfg.Scan.Network.IsValid() {
		t.Errorf("scan.network = %s, want cleared (detect)", m.cfg.Scan.Network)
	}
}

func TestScanOptionsError(t *testing.T) {
	m := newModel(t, &fakes{}, settings.Default())
	m, _ = press(t, m, "down", "enter", "s") // en0 has no options in the fake
	if m.screen != screenMain || !m.statusErr || !strings.Contains(m.status, "cannot scan en0") {
		t.Errorf("screen = %v, status = %q", m.screen, m.status)
	}
}
