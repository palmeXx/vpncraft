package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateVersion(t *testing.T) {
	for v, ok := range map[string]bool{
		"0.1.0": true, "1.2.3": true, "1.2.3-rc.1": true, "1.2.3-beta": true,
		"v1.2.3": false, "1.2": false, "1.2.3.4": false, "01.2.3": false, "": false, "1.2.3+build": false,
	} {
		if err := validateVersion(v); (err == nil) != ok {
			t.Errorf("validateVersion(%q) = %v, want ok=%v", v, err, ok)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"0.2.0", "0.1.9", 1},
		{"0.10.0", "0.9.0", 1},
		{"1.0.0", "1.0.0-rc.1", 1},
		{"1.0.0-rc.2", "1.0.0-rc.10", -1},
		{"1.0.0", "1.0.0", 0},
	}
	for _, tt := range tests {
		if got := compareVersions(tt.a, tt.b); got != tt.want {
			t.Errorf("compareVersions(%s, %s) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
	if !isPrerelease("1.0.0-rc.1") || isPrerelease("1.0.0") {
		t.Error("isPrerelease misclassifies")
	}
}

const testChangelog = `# Changelog

## [Unreleased]

## [0.2.0] - 2026-02-01

### Added

- Something new

## [0.1.0] - 2026-01-01

First release.
`

func TestChangelogSection(t *testing.T) {
	if got := changelogSection(testChangelog, "0.2.0"); got != "### Added\n\n- Something new" {
		t.Errorf("section 0.2.0 = %q", got)
	}
	if got := changelogSection(testChangelog, "0.1.0"); got != "First release." {
		t.Errorf("section 0.1.0 = %q", got)
	}
	if got := changelogSection(testChangelog, "0.3.0"); got != "" {
		t.Errorf("section 0.3.0 = %q, want empty", got)
	}
	if got := changelogSection(testChangelog, "0.1"); got != "" {
		t.Errorf("prefix match: %q", got)
	}
}

func TestBuildManifest(t *testing.T) {
	dist := t.TempDir()
	for name, content := range map[string]string{
		"vpncraft_linux_amd64":       "linux",
		"vpncraft_windows_arm64.exe": "windows",
		"SHA256SUMS":                 "ignored",
		"vpncraft-old.zip":           "ignored",
	} {
		if err := os.WriteFile(filepath.Join(dist, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	data, err := buildManifest(dist, "1.2.3-rc.1", "abc1234", "2026-01-01T00:00:00Z")
	if err != nil {
		t.Fatalf("buildManifest() error = %v", err)
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if m.Version != "1.2.3-rc.1" || m.Tag != "v1.2.3-rc.1" || !m.Prerelease || m.Commit != "abc1234" {
		t.Errorf("manifest header = %+v", m)
	}
	if len(m.Assets) != 2 {
		t.Fatalf("assets = %+v, want 2", m.Assets)
	}
	a := m.Assets[0]
	if a.File != "vpncraft_linux_amd64" || a.OS != "linux" || a.Arch != "amd64" || a.Size != 5 ||
		a.SHA256 != "caf90169eefa5f807d577486b9f795ab86ae2983c5c20806cff959117e90af18" { // sha256("linux")
		t.Errorf("asset[0] = %+v", a)
	}
	if want := "https://github.com/palmeXx/vpncraft/releases/download/v1.2.3-rc.1/vpncraft_windows_arm64.exe"; m.Assets[1].URL != want {
		t.Errorf("url = %q, want %q", m.Assets[1].URL, want)
	}

	if _, err := buildManifest(t.TempDir(), "1.0.0", "", ""); err == nil {
		t.Error("buildManifest() error = nil for empty dist")
	}
}

// gitRepo creates a repository with an initial release v0.1.0.
func gitRepo(t *testing.T) repository {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	r := repository{dir: t.TempDir()}
	mustGit(t, r, "init", "-q", "-b", "main")
	mustGit(t, r, "config", "user.email", "test@example.com")
	mustGit(t, r, "config", "user.name", "Test")
	mustGit(t, r, "config", "commit.gpgsign", "false")
	mustGit(t, r, "config", "tag.gpgsign", "false")
	commitFiles(t, r, "first release", map[string]string{
		versionFile:   `{"version": "0.1.0"}`,
		changelogFile: testChangelog,
	})
	mustGit(t, r, "tag", "v0.1.0")
	return r
}

func mustGit(t *testing.T, r repository, args ...string) string {
	t.Helper()
	out, err := r.git(args...)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func commitFiles(t *testing.T, r repository, msg string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(r.dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mustGit(t, r, "add", ".")
	mustGit(t, r, "commit", "-q", "-m", msg)
}

func TestCheck(t *testing.T) {
	r := gitRepo(t)
	mustGit(t, r, "branch", "base")

	// Unchanged version: not greater, tag exists.
	_, err := r.check("base")
	var problems checkProblems
	if !errors.As(err, &problems) || len(problems) != 2 {
		t.Fatalf("check() unchanged = %v, want 2 problems", err)
	}

	// Bump without changelog section.
	commitFiles(t, r, "bump", map[string]string{versionFile: `{"version": "0.3.0"}`})
	if _, err := r.check("base"); !errors.As(err, &problems) || len(problems) != 1 || !strings.Contains(problems[0], "CHANGELOG.md") {
		t.Fatalf("check() without section = %v", err)
	}

	// Bump with section.
	commitFiles(t, r, "changelog", map[string]string{changelogFile: testChangelog + "\n## [0.3.0] - 2026-03-01\n\n- More\n"})
	if v, err := r.check("base"); err != nil || v != "0.3.0" {
		t.Fatalf("check() = %q, %v", v, err)
	}

	// Lower version than base.
	commitFiles(t, r, "downgrade", map[string]string{versionFile: `{"version": "0.0.9"}`})
	if _, err := r.check("base"); !errors.As(err, &problems) || !strings.Contains(problems.Error(), "greater than 0.1.0") {
		t.Fatalf("check() downgrade = %v", err)
	}

	// Unknown refs are reported, so check skips the comparison for a base without version.json.
	if _, err := r.version("does-not-exist"); err == nil {
		t.Error("version(unknown ref) error = nil")
	}
}

func TestVersionAndNotes(t *testing.T) {
	r := gitRepo(t)
	commitFiles(t, r, "add feature", map[string]string{versionFile: `{"version": "0.2.0"}`})

	if v, err := r.version("v0.1.0"); err != nil || v != "0.1.0" {
		t.Errorf("version(v0.1.0) = %q, %v", v, err)
	}
	if v, err := r.version(""); err != nil || v != "0.2.0" {
		t.Errorf("version() = %q, %v", v, err)
	}

	notes, err := r.notes("")
	if err != nil {
		t.Fatalf("notes() error = %v", err)
	}
	for _, want := range []string{"- Something new", "## Commits", "- add feature (", "/compare/v0.1.0...v0.2.0"} {
		if !strings.Contains(notes, want) {
			t.Errorf("notes miss %q:\n%s", want, notes)
		}
	}
	if strings.Contains(notes, "first release") {
		t.Errorf("notes contain commits of the previous release:\n%s", notes)
	}

	// The first release has no previous tag and lists all commits.
	first, err := r.notes("v0.1.0")
	if err != nil || !strings.Contains(first, "- first release (") || strings.Contains(first, "compare") {
		t.Errorf("notes(v0.1.0) = %q, %v", first, err)
	}
}

func TestRunCommands(t *testing.T) {
	r := gitRepo(t)
	t.Chdir(r.dir)

	var out bytes.Buffer
	if err := run([]string{"version"}, &out); err != nil || out.String() != "0.1.0\n" {
		t.Errorf("run(version) = %q, %v", out.String(), err)
	}
	if err := run([]string{"bogus"}, &out); err == nil {
		t.Error("run(bogus) error = nil")
	}
	if err := run([]string{"check"}, &out); err == nil {
		t.Error("run(check) without --base error = nil")
	}
	notesFile := filepath.Join(t.TempDir(), "notes.md")
	if err := run([]string{"notes", "--output", notesFile}, &out); err != nil {
		t.Fatalf("run(notes) error = %v", err)
	}
	if data, _ := os.ReadFile(notesFile); !strings.Contains(string(data), "First release.") {
		t.Errorf("notes file = %q", data)
	}
}
