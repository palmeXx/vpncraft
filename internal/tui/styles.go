package tui

import (
	"fmt"
	"strings"

	"charm.land/lipgloss/v2"
)

var (
	colorAccent = lipgloss.Color("#7D56F4")
	colorVPN    = lipgloss.Color("#04B575")
	colorError  = lipgloss.Color("#FF5F87")
	colorDim    = lipgloss.Color("#6C6C6C")

	titleStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFFFFF")).Background(colorAccent).Padding(0, 1)
	crumbStyle    = lipgloss.NewStyle().Foreground(colorDim)
	headingStyle  = lipgloss.NewStyle().Bold(true).Foreground(colorAccent)
	labelStyle    = lipgloss.NewStyle().Foreground(colorDim).Width(11)
	cursorStyle   = lipgloss.NewStyle().Bold(true).Foreground(colorAccent)
	selectedStyle = lipgloss.NewStyle().Bold(true)
	vpnStyle      = lipgloss.NewStyle().Foreground(colorVPN)
	vpnTagStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#000000")).Background(colorVPN).Padding(0, 1)
	dimStyle      = lipgloss.NewStyle().Foreground(colorDim)
	errorStyle    = lipgloss.NewStyle().Foreground(colorError)
	okStyle       = lipgloss.NewStyle().Foreground(colorVPN)
	helpKeyStyle  = lipgloss.NewStyle().Bold(true)
	helpDescStyle = lipgloss.NewStyle().Foreground(colorDim)
	activeMode    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFFFFF")).Background(colorAccent).Padding(0, 1)
	inactiveMode  = lipgloss.NewStyle().Foreground(colorDim).Padding(0, 1)
)

// keyHelp is one entry of the footer key legend.
type keyHelp struct{ key, desc string }

func renderHelp(items ...keyHelp) string {
	parts := make([]string, len(items))
	for i, it := range items {
		parts[i] = helpKeyStyle.Render(it.key) + " " + helpDescStyle.Render(it.desc)
	}
	return strings.Join(parts, helpDescStyle.Render(" · "))
}

func cursor(active bool) string {
	if active {
		return cursorStyle.Render("▸ ")
	}
	return "  "
}

func checkbox(checked bool) string {
	if checked {
		return okStyle.Render("[x]")
	}
	return "[ ]"
}

// progressBar renders a fixed-width bar for done/total.
func progressBar(done, total, width int) string {
	if total <= 0 || width <= 0 {
		return ""
	}
	filled := min(width, done*width/total)
	return okStyle.Render(strings.Repeat("█", filled)) + dimStyle.Render(strings.Repeat("░", width-filled)) +
		fmt.Sprintf(" %3d%%", done*100/total)
}

// window returns the [start, end) slice of n items to show in height rows so
// that cur stays visible.
func window(cur, n, height int) (start, end int) {
	if height <= 0 || n <= height {
		return 0, n
	}
	start = max(0, min(cur-height/2, n-height))
	return start, start + height
}
