package buildinfo

import (
	"strings"
	"testing"
)

func TestString(t *testing.T) {
	oldV, oldC, oldD := Version, Commit, Date
	t.Cleanup(func() { Version, Commit, Date = oldV, oldC, oldD })

	Version, Commit, Date = "v1.2.3", "abc1234", "2026-01-01T00:00:00Z"

	got := String()
	for _, want := range []string{"vpncraft v1.2.3", "commit abc1234", "built 2026-01-01T00:00:00Z"} {
		if !strings.Contains(got, want) {
			t.Errorf("String() = %q, missing %q", got, want)
		}
	}
}
