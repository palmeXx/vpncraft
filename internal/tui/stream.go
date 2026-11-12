package tui

import (
	"bytes"
	"context"
	"net/netip"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/palmeXx/vpncraft/internal/app"
)

// Background operations (scan, run) report through a channel. Every message
// carries the generation of the operation that produced it so that late
// messages of a cancelled operation are ignored.

type scanProgressMsg struct {
	gen int
	p   app.Progress
}

type scanDoneMsg struct {
	gen   int
	peers []netip.Addr
	err   error
}

type logLineMsg struct {
	gen  int
	line string
}

type runDoneMsg struct {
	gen int
	err error
}

type savedMsg struct {
	path string
	err  error
}

// listen returns a command that delivers the next message from ch.
func listen(ch <-chan tea.Msg) tea.Cmd {
	return func() tea.Msg {
		msg, ok := <-ch
		if !ok {
			return nil
		}
		return msg
	}
}

// lineWriter turns written output into logLineMsgs, one per line. Carriage
// returns (progress redraws) are treated as line breaks.
type lineWriter struct {
	ctx context.Context
	gen int
	ch  chan<- tea.Msg
	buf bytes.Buffer
}

func (w *lineWriter) Write(p []byte) (int, error) {
	w.buf.Write(p)
	for {
		data := w.buf.Bytes()
		i := bytes.IndexAny(data, "\r\n")
		if i < 0 {
			return len(p), nil
		}
		line := strings.TrimRight(string(data[:i]), " ")
		w.buf.Next(i + 1)
		if line == "" {
			continue
		}
		select {
		case w.ch <- logLineMsg{gen: w.gen, line: line}:
		case <-w.ctx.Done():
			// Stopping: drop remaining output instead of blocking the capture loop.
		}
	}
}
