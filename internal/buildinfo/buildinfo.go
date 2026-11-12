// Package buildinfo exposes version metadata injected at link time via
//
//	-ldflags "-X github.com/palmeXx/vpncraft/internal/buildinfo.Commit=<sha> ..."
package buildinfo

import (
	"fmt"
	"runtime"
)

// Values are overwritten by the linker. Defaults apply to plain `go build`/`go run`.
var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

// String returns a single-line, human-readable build description.
func String() string {
	return fmt.Sprintf("vpncraft %s (commit %s, built %s, %s/%s, %s)",
		Version, Commit, Date, runtime.GOOS, runtime.GOARCH, runtime.Version())
}
