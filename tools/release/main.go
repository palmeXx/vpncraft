// Command release contains the helpers of the pull request check and the
// release workflow. It is a development tool and not part of the binaries.
//
//	release check --base origin/main        version bump and changelog of a pull request
//	release version [--ref v0.2.0]          version from version.json (working tree or git ref)
//	release notes [--ref v0.2.0] [--output notes.md]
//	release manifest --dist dist [--commit abc1234] [--output dist/manifest.json]
//
// Versions follow semantic versioning without "v" (0.2.0, 0.2.0-rc.1); tags
// carry a "v" prefix (v0.2.0), as Go modules require. The release notes are
// the section of the version in CHANGELOG.md, followed by the commits since
// the previous tag. CHANGELOG.md is always read from the working tree.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		if problems, ok := errors.AsType[checkProblems](err); ok {
			for _, p := range problems {
				// GitHub Actions annotation format.
				fmt.Fprintf(os.Stderr, "::error::%s\n", p)
			}
		} else {
			fmt.Fprintf(os.Stderr, "release: %v\n", err)
		}
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: release check|version|notes|manifest [flags]")
	}
	repo := repository{dir: "."}
	cmd, args := args[0], args[1:]
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)

	switch cmd {
	case "check":
		base := fs.String("base", "", "git ref of the pull request base, e.g. origin/main")
		if err := fs.Parse(args); err != nil {
			return err
		}
		if *base == "" {
			return errors.New("check: --base is required")
		}
		version, err := repo.check(*base)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(out, "Version %s is ready to be released as %s\n", version, tagOf(version))
		return err

	case "version":
		ref := fs.String("ref", "", "git ref, the working tree by default")
		if err := fs.Parse(args); err != nil {
			return err
		}
		version, err := repo.version(*ref)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, version)
		return err

	case "notes":
		ref := fs.String("ref", "", "git ref, the working tree by default")
		output := fs.String("output", "", "file for the notes, stdout by default")
		if err := fs.Parse(args); err != nil {
			return err
		}
		notes, err := repo.notes(*ref)
		if err != nil {
			return err
		}
		return writeOutput(*output, out, []byte(notes))

	case "manifest":
		dist := fs.String("dist", "dist", "directory with the release binaries")
		commit := fs.String("commit", "", "commit of the build")
		date := fs.String("date", "", "build date (RFC 3339)")
		output := fs.String("output", "", "file for the manifest, stdout by default")
		if err := fs.Parse(args); err != nil {
			return err
		}
		version, err := repo.version("")
		if err != nil {
			return err
		}
		data, err := buildManifest(*dist, version, *commit, *date)
		if err != nil {
			return err
		}
		return writeOutput(*output, out, data)
	}
	return fmt.Errorf("unknown command %q", cmd)
}

func writeOutput(path string, out io.Writer, data []byte) error {
	if path == "" {
		_, err := out.Write(data)
		return err
	}
	return os.WriteFile(path, data, 0o644) //nolint:gosec // release asset, world-readable on purpose
}
