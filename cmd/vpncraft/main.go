// Command vpncraft is a Warcraft III LAN packet sniffer and UDP relay for VPNs.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/term"

	"github.com/palmeXx/vpncraft/internal/app"
	"github.com/palmeXx/vpncraft/internal/buildinfo"
	"github.com/palmeXx/vpncraft/internal/capture"
	"github.com/palmeXx/vpncraft/internal/settings"
	"github.com/palmeXx/vpncraft/internal/tui"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr, isTerminal())
	stop()
	os.Exit(code)
}

func isTerminal() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, tty bool) int {
	opts, err := parseFlags(args, stderr)
	if err != nil {
		if errors.Is(err, errHelp) {
			return 0
		}
		_, _ = fmt.Fprintf(stderr, "[!] %v\n", err)
		return 2
	}

	if opts.showVersion {
		_, _ = fmt.Fprintf(stdout, "[*] %s\n", buildinfo.String())
		return 0
	}

	fileCfg, cfgPath, found, err := settings.Resolve(opts.configPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "[!] Invalid configuration: %v\n", err)
		return 2
	}
	cfg, err := opts.apply(fileCfg)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "[!] %v\n", strings.ReplaceAll(err.Error(), "\n", "; "))
		return 2
	}

	if opts.interactive() && tty {
		if err := tui.Run(ctx, cfg, cfgPath); err != nil {
			_, _ = fmt.Fprintf(stderr, "[!] TUI error: %v\n", err)
			return 1
		}
		return 0
	}

	_, _ = fmt.Fprintf(stdout, "[*] %s\n", buildinfo.String())
	if found {
		_, _ = fmt.Fprintf(stdout, "[*] Using config %s\n", cfgPath)
	}

	err = app.Run(ctx, cfg, stdout)
	var notFound *app.InterfaceNotFoundError
	switch {
	case errors.As(err, &notFound):
		writeInterfaceHint(stderr, notFound, cfgPath, found)
		return 2
	case errors.Is(err, capture.ErrPermission) || errors.Is(err, os.ErrPermission):
		_, _ = fmt.Fprintln(stderr, "\n[!] Error: Root/Admin privileges required.")
		return 1
	case err != nil:
		_, _ = fmt.Fprintf(stderr, "\n[!] Error: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "\n[*] Stopped [%s] mode.\n", strings.ToUpper(cfg.Mode))
	return 0
}

// writeInterfaceHint explains a missing interface, lists likely VPN
// interfaces and tells the user how to configure one. Nothing is chosen
// automatically.
func writeInterfaceHint(w io.Writer, e *app.InterfaceNotFoundError, cfgPath string, found bool) {
	_, _ = fmt.Fprintf(w, "\n[!] Error: %v\n", e)
	if len(e.Candidates) == 0 {
		_, _ = fmt.Fprintln(w, "[!] No likely VPN interface found. Is the VPN connected?")
		_, _ = fmt.Fprintln(w, "    Run `vpncraft` in a terminal to list all interfaces in the TUI.")
		return
	}

	_, _ = fmt.Fprintln(w, "[*] Likely VPN interfaces:")
	for _, n := range e.Candidates {
		addrs := make([]string, len(n.Addrs))
		for i, a := range n.Addrs {
			addrs[i] = a.String()
		}
		_, _ = fmt.Fprintf(w, "      %-12s %-20s (%s)\n", n.Name, strings.Join(addrs, ", "), n.VPNReason)
	}

	example := e.Candidates[0].Name
	switch {
	case found:
		_, _ = fmt.Fprintf(w, "[*] Set it in your config %s, e.g.:\n", cfgPath)
	case cfgPath != "":
		_, _ = fmt.Fprintf(w, "[*] Or create the config file %s, e.g.:\n", cfgPath)
	default:
		_, _ = fmt.Fprintln(w, "[*] Or create a config file (see config.example.yaml), e.g.:")
	}
	_, _ = fmt.Fprintf(w, "\n      interface: %s\n\n", example)
	_, _ = fmt.Fprintf(w, "    or pass it with -i %s, or run `vpncraft` in a terminal to choose it in the TUI.\n", example)
}
