// Package tui is the interactive terminal UI: pick a NIC, build a peer group
// via ping scan, choose sniff or relay mode and run it.
package tui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/netip"
	"os"
	"slices"
	"strings"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/palmeXx/vpncraft/internal/app"
	"github.com/palmeXx/vpncraft/internal/buildinfo"
	"github.com/palmeXx/vpncraft/internal/capture"
	"github.com/palmeXx/vpncraft/internal/netutil"
	"github.com/palmeXx/vpncraft/internal/settings"
)

const (
	maxLogLines  = 1000
	eventBuffer  = 256
	chromeHeight = 5 // header, blank, status, help, spare
	barWidth     = 30
)

type screen int

const (
	screenNICs screen = iota
	screenMain
	screenRange
	screenScan
	screenRun
)

// inputMode selects what the text input is used for.
type inputMode int

const (
	inputNone inputMode = iota
	inputPeer
	inputRange
)

// Deps are the side-effecting operations used by the UI, replaceable in tests.
type Deps struct {
	ListNICs    func() ([]netutil.NIC, error)
	ScanOptions func(iface string, scan settings.Scan) (netip.Addr, []app.ScanOption, int, error)
	LookupNames func(ctx context.Context, addrs []netip.Addr) map[netip.Addr]string
	Scan        func(ctx context.Context, t app.ScanTarget, opts settings.Scan, progress func(app.Progress)) ([]netip.Addr, error)
	Run         func(ctx context.Context, cfg settings.Config, out io.Writer) error
	Save        func(path string, cfg settings.Config) error
}

// DefaultDeps uses the real network stack and config file.
func DefaultDeps() Deps {
	return Deps{
		ListNICs:    netutil.ListNICs,
		ScanOptions: app.ScanOptions,
		LookupNames: app.LookupNames,
		Scan:        app.Scan,
		Run:         app.Run,
		Save:        settings.Save,
	}
}

// Model is the Bubble Tea model of the UI.
type Model struct {
	deps    Deps
	cfg     settings.Config
	cfgPath string

	width, height int
	screen        screen
	status        string
	statusErr     bool

	allNICs   []netutil.NIC
	nics      []netutil.NIC // visible subset of allNICs
	nicCursor int
	showAll   bool // also list interfaces without IPv4

	peerCursor int
	inputMode  inputMode
	input      textinput.Model

	rangeLocal  netip.Addr
	rangeOpts   []app.ScanOption
	rangeCursor int

	// Background operation state (scan or run), see stream.go.
	gen     int
	cancel  context.CancelFunc
	events  chan tea.Msg
	busy    bool
	stopReq bool

	scanTarget   app.ScanTarget
	scanProgress app.Progress
	scanErr      error
	scanResults  []netip.Addr
	scanChecked  map[netip.Addr]bool
	scanCursor   int

	logLines []string
	runErr   error

	names map[netip.Addr]string // reverse-DNS cache, "" = looked up without result
}

// New creates the UI model. cfgPath is where 'w' saves the configuration.
func New(cfg settings.Config, cfgPath string, deps Deps) Model {
	in := textinput.New()
	in.CharLimit = len("255.255.255.255/32")
	return Model{deps: deps, cfg: cfg, cfgPath: cfgPath, input: in, names: make(map[netip.Addr]string)}
}

// Run starts the UI and blocks until the user quits.
func Run(ctx context.Context, cfg settings.Config, cfgPath string) error {
	_, err := tea.NewProgram(New(cfg, cfgPath, DefaultDeps()), tea.WithContext(ctx)).Run()
	if errors.Is(err, tea.ErrProgramKilled) && ctx.Err() != nil {
		return nil
	}
	return err
}

// Init loads the interface list and resolves names of configured peers.
func (m Model) Init() tea.Cmd {
	return tea.Batch(m.loadNICs, m.resolveNames(m.cfg.Peers))
}

type namesMsg map[netip.Addr]string

// resolveNames looks up host names for addresses not yet in the cache.
func (m Model) resolveNames(addrs []netip.Addr) tea.Cmd {
	var todo []netip.Addr
	for _, a := range addrs {
		if _, ok := m.names[a]; !ok {
			todo = append(todo, a)
		}
	}
	if len(todo) == 0 || m.deps.LookupNames == nil {
		return nil
	}
	lookup := m.deps.LookupNames
	return func() tea.Msg {
		found := lookup(context.Background(), todo)
		msg := make(namesMsg, len(todo))
		for _, a := range todo {
			msg[a] = found[a] // "" marks "no name", so it is not looked up again
		}
		return msg
	}
}

// displayAddr renders an address with its host name, if known.
func (m Model) displayAddr(a netip.Addr) string {
	s := fmt.Sprintf("%-15s", a)
	if name := m.names[a]; name != "" {
		s += "  " + dimStyle.Render(name)
	}
	return s
}

type nicsMsg struct {
	nics []netutil.NIC
	err  error
}

func (m Model) loadNICs() tea.Msg {
	nics, err := m.deps.ListNICs()
	return nicsMsg{nics: nics, err: err}
}

// Update handles input and background events.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil
	case nicsMsg:
		return m.onNICs(msg), nil
	case namesMsg:
		maps.Copy(m.names, msg)
		return m, nil
	case savedMsg:
		if msg.err != nil {
			m.setError("save failed: %v", msg.err)
		} else {
			m.setStatus("saved to %s", msg.path)
		}
		return m, nil
	case scanProgressMsg:
		if msg.gen == m.gen {
			m.scanProgress = msg.p
		}
		return m, listen(m.events)
	case scanDoneMsg:
		m = m.onScanDone(msg)
		return m, m.resolveNames(m.scanResults)
	case logLineMsg:
		if msg.gen == m.gen {
			m.appendLog(msg.line)
		}
		return m, listen(m.events)
	case runDoneMsg:
		return m.onRunDone(msg), nil
	case tea.KeyPressMsg:
		return m.onKey(msg)
	}
	return m, nil
}

func (m Model) onNICs(msg nicsMsg) Model {
	if msg.err != nil {
		m.setError("%v", msg.err)
		return m
	}
	m.allNICs = msg.nics
	// Pre-select the configured interface, else the first VPN candidate (sorted first).
	m.filterNICs(m.cfg.Interface)
	return m
}

// filterNICs rebuilds the visible list and keeps the cursor on keep if shown.
// Interfaces without IPv4 are hidden unless showAll is set or configured.
func (m *Model) filterNICs(keep string) {
	m.nics = m.nics[:0:0]
	for _, n := range m.allNICs {
		if m.showAll || len(n.Addrs) > 0 || n.Name == m.cfg.Interface {
			m.nics = append(m.nics, n)
		}
	}
	m.nicCursor = 0
	for i, n := range m.nics {
		if n.Name == keep {
			m.nicCursor = i
			break
		}
	}
}

func (m Model) currentNIC() string {
	if m.nicCursor < len(m.nics) {
		return m.nics[m.nicCursor].Name
	}
	return ""
}

func (m Model) onKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	key := msg.String()
	if key == "ctrl+c" {
		m.stop()
		return m, tea.Quit
	}
	if m.inputMode != inputNone {
		return m.onInputKey(msg)
	}
	switch m.screen {
	case screenNICs:
		return m.onNICKey(key)
	case screenMain:
		return m.onMainKey(key)
	case screenRange:
		return m.onRangeKey(key)
	case screenScan:
		return m.onScanKey(key)
	case screenRun:
		return m.onRunKey(key)
	}
	return m, nil
}

func (m Model) onNICKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "up", "k":
		m.nicCursor = max(0, m.nicCursor-1)
	case "down", "j":
		m.nicCursor = max(0, min(len(m.nics)-1, m.nicCursor+1))
	case "r":
		m.setStatus("interfaces refreshed")
		return m, m.loadNICs
	case "h":
		m.showAll = !m.showAll
		m.filterNICs(m.currentNIC())
		m.setStatus("%d of %d interfaces shown", len(m.nics), len(m.allNICs))
	case "enter", "space":
		if len(m.nics) == 0 {
			return m, nil
		}
		m.cfg.Interface = m.nics[m.nicCursor].Name
		m.screen = screenMain
		m.setStatus("interface %s selected", m.cfg.Interface)
	case "q", "esc":
		return m, tea.Quit
	}
	return m, nil
}

func (m Model) onMainKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "up", "k":
		m.peerCursor = max(0, m.peerCursor-1)
	case "down", "j":
		m.peerCursor = max(0, min(len(m.cfg.Peers)-1, m.peerCursor+1))
	case "m", "tab":
		if m.cfg.Mode == settings.ModeRelay {
			m.cfg.Mode = settings.ModeSniff
		} else {
			m.cfg.Mode = settings.ModeRelay
		}
	case "s":
		return m.openRangeSelection()
	case "a":
		return m, m.openInput(inputPeer, "Peer IPv4: ", "100.64.0.2")
	case "d", "delete", "backspace":
		if len(m.cfg.Peers) > 0 {
			removed := m.cfg.Peers[m.peerCursor]
			m.cfg.Peers = slices.Delete(m.cfg.Peers, m.peerCursor, m.peerCursor+1)
			m.peerCursor = max(0, min(m.peerCursor, len(m.cfg.Peers)-1))
			m.setStatus("removed %s from peer group", removed)
		}
	case "w":
		cfg, path, save := m.cfg, m.cfgPath, m.deps.Save
		return m, func() tea.Msg { return savedMsg{path: path, err: save(path, cfg)} }
	case "enter":
		return m.startRun()
	case "esc", "i":
		m.screen = screenNICs
	case "q":
		return m, tea.Quit
	}
	return m, nil
}

// openInput focuses the text input for mode.
func (m *Model) openInput(mode inputMode, prompt, placeholder string) tea.Cmd {
	m.inputMode = mode
	m.input.Prompt = prompt
	m.input.Placeholder = placeholder
	m.input.Reset()
	return m.input.Focus()
}

func (m *Model) closeInput() {
	m.inputMode = inputNone
	m.input.Blur()
}

func (m Model) onInputKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.closeInput()
		return m, nil
	case "enter":
		value := strings.TrimSpace(m.input.Value())
		if m.inputMode == inputRange {
			return m.submitRange(value)
		}
		addr, err := netip.ParseAddr(value)
		if err != nil || !addr.Is4() {
			m.setError("%q is not a valid IPv4 address", value)
			return m, nil
		}
		m.closeInput()
		m.addPeers(addr)
		m.setStatus("added %s to peer group", addr)
		return m, m.resolveNames([]netip.Addr{addr})
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

// openRangeSelection lists the scan ranges for the selected interface.
func (m Model) openRangeSelection() (tea.Model, tea.Cmd) {
	local, opts, def, err := m.deps.ScanOptions(m.cfg.Interface, m.cfg.Scan)
	if err != nil {
		m.setError("cannot scan %s: %v", m.cfg.Interface, err)
		return m, nil
	}
	m.rangeLocal, m.rangeOpts, m.rangeCursor = local, opts, def
	m.screen = screenRange
	m.setStatus("choose the range to scan")
	return m, nil
}

func (m Model) onRangeKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "up", "k":
		m.rangeCursor = max(0, m.rangeCursor-1)
	case "down", "j":
		m.rangeCursor = max(0, min(len(m.rangeOpts)-1, m.rangeCursor+1))
	case "enter", "space":
		if len(m.rangeOpts) == 0 {
			return m, nil
		}
		o := m.rangeOpts[m.rangeCursor]
		if !o.Allowed {
			m.setError("%s is too large to scan (%d hosts); choose a smaller range", o.Prefix, o.Hosts())
			return m, nil
		}
		network := o.Prefix
		if o.Detected {
			network = netip.Prefix{} // keep detecting automatically
		}
		return m.startScan(app.NewScanTarget(m.rangeLocal, o.Prefix, o.Label), network)
	case "c":
		return m, m.openInput(inputRange, "Scan range (CIDR): ", "100.64.12.0/24")
	case "esc", "q":
		m.screen = screenMain
	}
	return m, nil
}

func (m Model) submitRange(value string) (tea.Model, tea.Cmd) {
	p, err := netip.ParsePrefix(value)
	if err == nil {
		err = app.ValidateScanRange(p)
	}
	if err != nil {
		m.setError("invalid scan range %q: %v", value, err)
		return m, nil
	}
	m.closeInput()
	p = p.Masked()
	return m.startScan(app.NewScanTarget(m.rangeLocal, p, "custom"), p)
}

func (m Model) onScanKey(key string) (tea.Model, tea.Cmd) {
	if m.busy {
		if key == "esc" || key == "q" {
			m.stop()
			m.busy = false
			m.screen = screenMain
			m.setStatus("scan cancelled")
		}
		return m, nil
	}
	switch key {
	case "up", "k":
		m.scanCursor = max(0, m.scanCursor-1)
	case "down", "j":
		m.scanCursor = max(0, min(len(m.scanResults)-1, m.scanCursor+1))
	case "space":
		if len(m.scanResults) > 0 {
			a := m.scanResults[m.scanCursor]
			m.scanChecked[a] = !m.scanChecked[a]
		}
	case "a":
		all := !m.allChecked()
		for _, a := range m.scanResults {
			m.scanChecked[a] = all
		}
	case "enter":
		m.applyScanSelection()
		m.screen = screenMain
	case "esc", "q":
		m.screen = screenMain
		m.setStatus("scan results discarded")
	}
	return m, nil
}

func (m Model) onRunKey(key string) (tea.Model, tea.Cmd) {
	if !m.busy {
		if key == "esc" || key == "q" || key == "enter" {
			m.screen = screenMain
		}
		return m, nil
	}
	if key == "esc" || key == "q" {
		m.stopReq = true
		if m.cancel != nil {
			m.cancel()
		}
		m.setStatus("stopping…")
	}
	return m, nil
}

// startScan launches a ping sweep of target and remembers network as
// scan.network (invalid = detect automatically), so 'w' persists the choice.
func (m Model) startScan(target app.ScanTarget, network netip.Prefix) (tea.Model, tea.Cmd) {
	m.cfg.Scan.Network = network
	ctx, ch := m.begin()
	m.screen = screenScan
	m.scanTarget = target
	m.scanProgress = app.Progress{Total: len(target.Hosts)}
	m.scanErr = nil
	m.scanResults = nil
	m.scanCursor = 0
	m.setStatus("scanning %s…", target.Prefix)

	gen, scan, opts := m.gen, m.deps.Scan, m.cfg.Scan
	go func() {
		peers, err := scan(ctx, target, opts, func(p app.Progress) {
			select {
			case ch <- scanProgressMsg{gen: gen, p: p}:
			default: // UI is behind; skip this update
			}
		})
		ch <- scanDoneMsg{gen: gen, peers: peers, err: err}
		close(ch)
	}()
	return m, listen(ch)
}

func (m Model) onScanDone(msg scanDoneMsg) Model {
	if msg.gen != m.gen {
		return m
	}
	m.busy = false
	m.cancel = nil
	if m.screen != screenScan {
		return m
	}
	if msg.err != nil && !errors.Is(msg.err, context.Canceled) {
		m.scanErr = msg.err
		m.setError("scan failed: %s", describeErr(msg.err))
	} else {
		m.setStatus("scan finished: %d peer(s) responded", len(msg.peers))
	}
	m.scanResults = msg.peers
	m.scanChecked = make(map[netip.Addr]bool, len(msg.peers))
	for _, p := range msg.peers {
		m.scanChecked[p] = slices.Contains(m.cfg.Peers, p)
	}
	return m
}

// applyScanSelection merges checked results into the peer group and removes
// unchecked results that were members before.
func (m *Model) applyScanSelection() {
	var added, removed int
	for _, a := range m.scanResults {
		inGroup := slices.Contains(m.cfg.Peers, a)
		switch {
		case m.scanChecked[a] && !inGroup:
			m.cfg.Peers = append(m.cfg.Peers, a)
			added++
		case !m.scanChecked[a] && inGroup:
			m.cfg.Peers = slices.DeleteFunc(m.cfg.Peers, func(p netip.Addr) bool { return p == a })
			removed++
		}
	}
	m.normalizePeers()
	m.setStatus("peer group updated: +%d / -%d (%d total)", added, removed, len(m.cfg.Peers))
}

func (m *Model) allChecked() bool {
	for _, a := range m.scanResults {
		if !m.scanChecked[a] {
			return false
		}
	}
	return len(m.scanResults) > 0
}

// startRun runs the selected mode with the current peer group.
func (m Model) startRun() (tea.Model, tea.Cmd) {
	cfg := m.cfg
	cfg.Peers = slices.Clone(m.cfg.Peers)
	cfg.Scan.Enabled = false // the peer group is managed interactively
	if err := cfg.Validate(); err != nil {
		m.setError("%v", err)
		return m, nil
	}

	ctx, ch := m.begin()
	m.screen = screenRun
	m.logLines = nil
	m.runErr = nil
	m.stopReq = false
	m.setStatus("running %s on %s", strings.ToUpper(cfg.Mode), cfg.Interface)

	gen, run := m.gen, m.deps.Run
	go func() {
		err := run(ctx, cfg, &lineWriter{ctx: ctx, gen: gen, ch: ch})
		ch <- runDoneMsg{gen: gen, err: err}
		close(ch)
	}()
	return m, listen(ch)
}

func (m Model) onRunDone(msg runDoneMsg) Model {
	if msg.gen != m.gen {
		return m
	}
	m.busy = false
	m.cancel = nil
	m.runErr = msg.err
	switch {
	case msg.err != nil:
		m.setError("stopped with error: %s", describeErr(msg.err))
	case m.stopReq:
		m.screen = screenMain
		m.setStatus("%s stopped", strings.ToUpper(m.cfg.Mode))
	default:
		m.setStatus("%s finished", strings.ToUpper(m.cfg.Mode))
	}
	return m
}

// begin starts a new background operation generation.
func (m *Model) begin() (context.Context, chan tea.Msg) {
	m.stop()
	m.gen++
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	m.events = make(chan tea.Msg, eventBuffer)
	m.busy = true
	return ctx, m.events
}

// stop cancels the current background operation, if any.
func (m *Model) stop() {
	if m.cancel != nil {
		m.cancel()
		m.cancel = nil
	}
}

func (m *Model) addPeers(addrs ...netip.Addr) {
	m.cfg.Peers = append(m.cfg.Peers, addrs...)
	m.normalizePeers()
}

func (m *Model) normalizePeers() {
	slices.SortFunc(m.cfg.Peers, netip.Addr.Compare)
	m.cfg.Peers = slices.Compact(m.cfg.Peers)
	m.peerCursor = max(0, min(m.peerCursor, len(m.cfg.Peers)-1))
}

func (m *Model) appendLog(line string) {
	m.logLines = append(m.logLines, line)
	if over := len(m.logLines) - maxLogLines; over > 0 {
		m.logLines = slices.Delete(m.logLines, 0, over)
	}
}

func (m *Model) setStatus(format string, args ...any) {
	m.status, m.statusErr = fmt.Sprintf(format, args...), false
}

func (m *Model) setError(format string, args ...any) {
	m.status, m.statusErr = fmt.Sprintf(format, args...), true
}

func describeErr(err error) string {
	if errors.Is(err, capture.ErrPermission) || errors.Is(err, os.ErrPermission) {
		return "root/Administrator privileges required (start with sudo)"
	}
	return err.Error()
}

// View renders the current screen.
func (m Model) View() tea.View {
	var body string
	var help []keyHelp
	switch m.screen {
	case screenNICs:
		body, help = m.viewNICs()
	case screenMain:
		body, help = m.viewMain()
	case screenRange:
		body, help = m.viewRange()
	case screenScan:
		body, help = m.viewScan()
	case screenRun:
		body, help = m.viewRun()
	}

	status := ""
	if m.status != "" {
		status = okStyle.Render("● ") + m.status
		if m.statusErr {
			status = errorStyle.Render("✗ " + m.status)
		}
	}

	content := lipgloss.JoinVertical(lipgloss.Left,
		m.viewHeader(),
		"",
		body,
		"",
		status,
		renderHelp(append(help, keyHelp{"ctrl+c", "quit"})...),
	)
	v := tea.NewView(content)
	v.AltScreen = true
	v.WindowTitle = "vpncraft"
	return v
}

func (m Model) viewHeader() string {
	crumbs := []string{"Interfaces"}
	if m.screen != screenNICs {
		crumbs = append(crumbs, m.cfg.Interface)
	}
	switch m.screen {
	case screenRange:
		crumbs = append(crumbs, "Scan range")
	case screenScan:
		crumbs = append(crumbs, "Scan")
	case screenRun:
		crumbs = append(crumbs, strings.ToUpper(m.cfg.Mode))
	}
	title := titleStyle.Render("vpncraft " + buildinfo.Version)
	return title + " " + crumbStyle.Render(strings.Join(crumbs, " › ")+"  ·  commit "+buildinfo.Commit)
}

// listHeight is the number of rows available for a list with extra fixed rows.
func (m Model) listHeight(extra int) int {
	if m.height == 0 {
		return 0 // unknown: render everything
	}
	return max(3, m.height-chromeHeight-extra)
}

func (m Model) viewNICs() (string, []keyHelp) {
	var b strings.Builder
	b.WriteString(headingStyle.Render("Select network interface") + dimStyle.Render("  (likely VPN interfaces are highlighted)") + "\n\n")
	if len(m.nics) == 0 {
		b.WriteString(dimStyle.Render("no interfaces found"))
	}
	start, end := window(m.nicCursor, len(m.nics), m.listHeight(2))
	for i := start; i < end; i++ {
		b.WriteString(m.renderNIC(i) + "\n")
	}
	return strings.TrimRight(b.String(), "\n"), []keyHelp{
		{"↑/↓", "move"}, {"enter", "select"}, {"h", hideLabel(m.showAll)}, {"r", "refresh"}, {"q", "quit"},
	}
}

func (m Model) renderNIC(i int) string {
	n := m.nics[i]
	addrs := make([]string, len(n.Addrs))
	for j, a := range n.Addrs {
		addrs[j] = a.String()
	}
	addr := strings.Join(addrs, ", ")
	if addr == "" {
		addr = "–"
	}
	line := fmt.Sprintf("%-16s %-34s", n.Name, addr)

	var tags []string
	switch {
	case n.VPN:
		line = vpnStyle.Bold(i == m.nicCursor).Render(line)
		tags = append(tags, vpnTagStyle.Render("VPN"), dimStyle.Render(n.VPNReason))
	case !n.Up:
		line = dimStyle.Render(line)
		tags = append(tags, dimStyle.Render("down"))
	case n.Loopback:
		line = dimStyle.Render(line)
		tags = append(tags, dimStyle.Render("loopback"))
	case i == m.nicCursor:
		line = selectedStyle.Render(line)
	}
	if n.Name == m.cfg.Interface {
		tags = append(tags, dimStyle.Render("(configured)"))
	}
	return cursor(i == m.nicCursor) + line + " " + strings.Join(tags, " ")
}

func (m Model) viewMain() (string, []keyHelp) {
	var b strings.Builder

	nicInfo := []string{m.cfg.Interface}
	for _, n := range m.allNICs {
		if n.Name == m.cfg.Interface {
			for _, a := range n.Addrs {
				nicInfo = append(nicInfo, a.String())
			}
			if n.VPN {
				nicInfo = append(nicInfo, vpnTagStyle.Render("VPN"))
			}
		}
	}
	b.WriteString(labelStyle.Render("Interface") + strings.Join(nicInfo, "  ") + "\n")

	sniffLabel, relayLabel := inactiveMode.Render("sniff"), activeMode.Render("relay")
	if m.cfg.Mode == settings.ModeSniff {
		sniffLabel, relayLabel = activeMode.Render("sniff"), inactiveMode.Render("relay")
	}
	b.WriteString(labelStyle.Render("Mode") + sniffLabel + " " + relayLabel + "\n")
	cfgPath := m.cfgPath
	if cfgPath == "" {
		cfgPath = "(no config path)"
	}
	b.WriteString(labelStyle.Render("Config") + dimStyle.Render(cfgPath) + "\n\n")

	b.WriteString(headingStyle.Render(fmt.Sprintf("Peer group (%d)", len(m.cfg.Peers))) + "\n")
	if len(m.cfg.Peers) == 0 {
		b.WriteString(dimStyle.Render("  empty – press s to scan the VPN subnet or a to add a peer") + "\n")
	}
	start, end := window(m.peerCursor, len(m.cfg.Peers), m.listHeight(7))
	for i := start; i < end; i++ {
		line := m.displayAddr(m.cfg.Peers[i])
		if i == m.peerCursor {
			line = selectedStyle.Render(line)
		}
		b.WriteString(cursor(i == m.peerCursor) + line + "\n")
	}
	if m.inputMode == inputPeer {
		b.WriteString("\n" + m.input.View() + "\n")
		return strings.TrimRight(b.String(), "\n"), []keyHelp{{"enter", "add"}, {"esc", "cancel"}}
	}
	return strings.TrimRight(b.String(), "\n"), []keyHelp{
		{"enter", "start"}, {"m", "mode"}, {"s", "scan peers"}, {"a", "add"}, {"d", "remove"},
		{"w", "save config"}, {"esc", "interfaces"}, {"q", "quit"},
	}
}

func (m Model) viewRange() (string, []keyHelp) {
	var b strings.Builder
	b.WriteString(headingStyle.Render("Select scan range") +
		dimStyle.Render(fmt.Sprintf("  %s, local IP %s", m.cfg.Interface, m.rangeLocal)) + "\n\n")
	for i, o := range m.rangeOpts {
		line := fmt.Sprintf("%-18s %10d hosts   %s", o.Prefix, o.Hosts(), o.Label)
		switch {
		case !o.Allowed:
			line = dimStyle.Render(line + fmt.Sprintf("  – too large (max /%d)", settings.MaxScanBits))
		case i == m.rangeCursor:
			line = selectedStyle.Render(line)
		}
		b.WriteString(cursor(i == m.rangeCursor) + line + "\n")
	}
	if m.inputMode == inputRange {
		b.WriteString("\n" + m.input.View() + "\n")
		return strings.TrimRight(b.String(), "\n"), []keyHelp{{"enter", "scan"}, {"esc", "cancel"}}
	}
	return strings.TrimRight(b.String(), "\n"), []keyHelp{
		{"↑/↓", "move"}, {"enter", "scan"}, {"c", "custom CIDR"}, {"esc", "back"},
	}
}

func (m Model) viewScan() (string, []keyHelp) {
	var b strings.Builder
	t := m.scanTarget
	b.WriteString(headingStyle.Render(fmt.Sprintf("Ping scan %s", t.Prefix)) +
		dimStyle.Render(fmt.Sprintf("  from %s (%s), %d hosts, network from %s", m.cfg.Interface, t.Local, len(t.Hosts), t.Source)) + "\n\n")

	p := m.scanProgress
	b.WriteString(progressBar(p.Sent, max(1, p.Total), barWidth) +
		fmt.Sprintf("  %d/%d  active %d  %.1fs", p.Sent, p.Total, p.Alive, p.Elapsed.Seconds()) + "\n\n")

	if m.busy {
		return strings.TrimRight(b.String(), "\n"), []keyHelp{{"esc", "cancel"}}
	}
	if m.scanErr != nil {
		b.WriteString(errorStyle.Render(describeErr(m.scanErr)) + "\n")
	}
	b.WriteString(headingStyle.Render(fmt.Sprintf("Responding hosts (%d)", len(m.scanResults))) + "\n")
	if len(m.scanResults) == 0 {
		b.WriteString(dimStyle.Render("  no host answered") + "\n")
	}
	start, end := window(m.scanCursor, len(m.scanResults), m.listHeight(6))
	for i := start; i < end; i++ {
		a := m.scanResults[i]
		line := m.displayAddr(a)
		if i == m.scanCursor {
			line = selectedStyle.Render(line)
		}
		note := ""
		if slices.Contains(m.cfg.Peers, a) {
			note = dimStyle.Render("  (in group)")
		}
		b.WriteString(cursor(i == m.scanCursor) + checkbox(m.scanChecked[a]) + " " + line + note + "\n")
	}
	return strings.TrimRight(b.String(), "\n"), []keyHelp{
		{"space", "toggle"}, {"a", "all/none"}, {"enter", "apply to group"}, {"esc", "discard"},
	}
}

func (m Model) viewRun() (string, []keyHelp) {
	var b strings.Builder
	title := fmt.Sprintf("%s on %s", strings.ToUpper(m.cfg.Mode), m.cfg.Interface)
	if m.cfg.Mode == settings.ModeRelay {
		title += fmt.Sprintf(" → %d peer(s)", len(m.cfg.Peers))
	}
	state := okStyle.Render("running")
	switch {
	case m.busy && m.stopReq:
		state = dimStyle.Render("stopping…")
	case !m.busy && m.runErr != nil:
		state = errorStyle.Render("failed")
	case !m.busy:
		state = dimStyle.Render("stopped")
	}
	b.WriteString(headingStyle.Render(title) + "  " + state + "\n\n")

	lines := m.logLines
	if h := m.listHeight(2); h > 0 && len(lines) > h {
		lines = lines[len(lines)-h:]
	}
	for _, l := range lines {
		b.WriteString(l + "\n")
	}
	if len(m.logLines) == 0 {
		b.WriteString(dimStyle.Render("waiting for output…"))
	}
	if m.busy {
		return strings.TrimRight(b.String(), "\n"), []keyHelp{{"esc", "stop"}}
	}
	return strings.TrimRight(b.String(), "\n"), []keyHelp{{"esc", "back"}}
}

func hideLabel(showAll bool) string {
	if showAll {
		return "hide no-IPv4"
	}
	return "show all"
}
