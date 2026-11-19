package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/mod/semver"
)

const (
	versionFile   = "version.json"
	changelogFile = "CHANGELOG.md"
	repositoryURL = "https://github.com/palmeXx/vpncraft"
)

// versionPattern accepts MAJOR.MINOR.PATCH with an optional pre-release suffix.
var versionPattern = regexp.MustCompile(`^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$`)

// checkProblems are the reasons a pull request is not releasable.
type checkProblems []string

func (p checkProblems) Error() string { return strings.Join(p, "; ") }

// repository runs git and reads release files relative to dir.
type repository struct {
	dir string
}

func (r repository) git(args ...string) (string, error) {
	cmd := exec.Command("git", args...) //nolint:gosec // fixed binary; arguments are refs/flags given by the maintainer or workflow, no shell involved
	cmd.Dir = r.dir
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
			return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(exitErr.Stderr)))
		}
		return "", fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(out)), nil
}

// tagOf returns the git tag of a version.
func tagOf(version string) string { return "v" + version }

// validateVersion checks the version format.
func validateVersion(version string) error {
	if !versionPattern.MatchString(version) || !semver.IsValid(tagOf(version)) {
		return fmt.Errorf("version %q isn't like 1.2.3 or 1.2.3-rc.1", version)
	}
	return nil
}

// isPrerelease reports versions with a pre-release suffix.
func isPrerelease(version string) bool { return semver.Prerelease(tagOf(version)) != "" }

// compareVersions orders versions by semantic versioning precedence.
func compareVersions(a, b string) int { return semver.Compare(tagOf(a), tagOf(b)) }

func parseVersionFile(data []byte) (string, error) {
	var v struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		return "", fmt.Errorf("parse %s: %w", versionFile, err)
	}
	if err := validateVersion(v.Version); err != nil {
		return "", fmt.Errorf("%s: %w", versionFile, err)
	}
	return v.Version, nil
}

// version returns the version at a git ref, or of the working tree if ref is empty.
func (r repository) version(ref string) (string, error) {
	var data []byte
	if ref == "" {
		var err error
		if data, err = os.ReadFile(filepath.Join(r.dir, versionFile)); err != nil {
			return "", err
		}
	} else {
		out, err := r.git("show", ref+":"+versionFile)
		if err != nil {
			return "", err
		}
		data = []byte(out)
	}
	return parseVersionFile(data)
}

func (r repository) tagExists(tag string) (bool, error) {
	out, err := r.git("tag", "--list", tag)
	return out != "", err
}

// changelogSection returns the body of the "## [version]" section, without heading.
func changelogSection(changelog, version string) string {
	heading := regexp.MustCompile(`(?m)^## \[` + regexp.QuoteMeta(version) + `\][^\n]*\n`)
	loc := heading.FindStringIndex(changelog)
	if loc == nil {
		return ""
	}
	rest := changelog[loc[1]:]
	if next := regexp.MustCompile(`(?m)^## \[`).FindStringIndex(rest); next != nil {
		rest = rest[:next[0]]
	}
	return strings.TrimSpace(rest)
}

func (r repository) changelog() (string, error) {
	data, err := os.ReadFile(filepath.Join(r.dir, changelogFile))
	return string(data), err
}

// check validates the working tree as the next release after base and
// returns its version, or checkProblems.
func (r repository) check(base string) (string, error) {
	version, err := r.version("")
	if err != nil {
		return "", err
	}
	var problems checkProblems

	// A base without version.json (first release) has nothing to compare against.
	if baseVersion, err := r.version(base); err == nil && compareVersions(version, baseVersion) <= 0 {
		problems = append(problems, fmt.Sprintf("version %s in %s has to be greater than %s on %s",
			version, versionFile, baseVersion, base))
	}
	exists, err := r.tagExists(tagOf(version))
	if err != nil {
		return "", err
	}
	if exists {
		problems = append(problems, fmt.Sprintf("tag %s exists already", tagOf(version)))
	}
	changelog, err := r.changelog()
	if err != nil {
		return "", err
	}
	if changelogSection(changelog, version) == "" {
		problems = append(problems, fmt.Sprintf("%s needs a section '## [%s] - <date>'", changelogFile, version))
	}
	if len(problems) > 0 {
		return "", problems
	}
	return version, nil
}

// notes builds the release notes of the version at ref (working tree if empty).
func (r repository) notes(ref string) (string, error) {
	version, err := r.version(ref)
	if err != nil {
		return "", err
	}
	changelog, err := r.changelog()
	if err != nil {
		return "", err
	}
	section := changelogSection(changelog, version)
	if section == "" {
		return "", fmt.Errorf("%s has no section '## [%s]'", changelogFile, version)
	}

	head := ref
	if head == "" {
		head = "HEAD"
	}
	tag := tagOf(version)
	previous, err := r.git("describe", "--tags", "--abbrev=0", "--match=v*", "--exclude="+tag, head)
	if err != nil {
		previous = "" // no earlier release
	}
	rangeArg := head
	if previous != "" {
		rangeArg = previous + ".." + head
	}
	commits, err := r.git("log", "--no-merges", "--pretty=format:- %s (%h)", rangeArg)
	if err != nil {
		return "", err
	}
	if commits == "" {
		commits = "- No commits"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\n## Commits\n\n%s\n", section, commits)
	if previous != "" {
		fmt.Fprintf(&b, "\n**Full changelog**: %s/compare/%s...%s\n", repositoryURL, previous, tag)
	}
	return b.String(), nil
}
