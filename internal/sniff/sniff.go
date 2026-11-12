// Package sniff logs captured Warcraft III LAN packets to stdout and files.
package sniff

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/palmeXx/vpncraft/internal/capture"
	"github.com/palmeXx/vpncraft/internal/wc3"
)

const (
	timeFormat = "2006-01-02 15:04:05"
	separator  = "------------------------------------------------------------"
	filePerm   = 0o644
)

// Logger appends a decoded text record and the raw payload of every W3GS packet.
type Logger struct {
	out  io.Writer
	text *os.File
	bin  *os.File
	now  func() time.Time
}

// NewLogger opens (or creates) the text log and binary dump in append mode.
func NewLogger(out io.Writer, textPath, binPath string) (*Logger, error) {
	text, err := os.OpenFile(textPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, filePerm)
	if err != nil {
		return nil, fmt.Errorf("open log file: %w", err)
	}
	bin, err := os.OpenFile(binPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, filePerm)
	if err != nil {
		_ = text.Close()
		return nil, fmt.Errorf("open binary dump: %w", err)
	}
	return &Logger{out: out, text: text, bin: bin, now: time.Now}, nil
}

// Handle records pkt if it carries a W3GS payload.
func (l *Logger) Handle(pkt capture.Packet) error {
	if !wc3.IsW3GS(pkt.Payload) {
		return nil
	}
	entry := FormatEntry(l.now(), pkt)
	_, _ = fmt.Fprintln(l.out, strings.TrimSpace(entry)+"\n")

	if _, err := io.WriteString(l.text, entry); err != nil {
		return fmt.Errorf("write log file: %w", err)
	}
	if _, err := l.bin.Write(pkt.Payload); err != nil {
		return fmt.Errorf("write binary dump: %w", err)
	}
	return nil
}

// Close flushes and closes both files.
func (l *Logger) Close() error {
	return errors.Join(l.text.Close(), l.bin.Close())
}

// FormatEntry renders one log record, including the trailing separator line.
func FormatEntry(ts time.Time, pkt capture.Packet) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[%s] Captured %d bytes from %s\n", ts.Format(timeFormat), len(pkt.Payload), pkt.Src)
	b.WriteString("Payload (Hex):\n")
	b.WriteString(hexSpaced(pkt.Payload))
	b.WriteString("\nDecoded Message:\n")
	b.WriteString(wc3.Describe(pkt.Payload, pkt.Src.Addr().String()))
	b.WriteString("\n" + separator + "\n")
	return b.String()
}

// hexSpaced formats b as lowercase hex bytes separated by single spaces.
func hexSpaced(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	out := make([]byte, 0, len(b)*3-1)
	for i, c := range b {
		if i > 0 {
			out = append(out, ' ')
		}
		out = hex.AppendEncode(out, []byte{c})
	}
	return string(out)
}
