package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"slices"
	"strings"
)

// assetPattern matches release binaries: vpncraft_<os>_<arch>[.exe].
var assetPattern = regexp.MustCompile(`^vpncraft_([a-z0-9]+)_([a-z0-9]+)(\.exe)?$`)

// Manifest is the machine-readable description of a release (manifest.json).
type Manifest struct {
	Name       string  `json:"name"`
	Version    string  `json:"version"`
	Tag        string  `json:"tag"`
	Prerelease bool    `json:"prerelease"`
	Commit     string  `json:"commit,omitempty"`
	Date       string  `json:"date,omitempty"`
	Repository string  `json:"repository"`
	Assets     []Asset `json:"assets"`
}

// Asset is one release binary.
type Asset struct {
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	File   string `json:"file"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	URL    string `json:"url"`
}

// buildManifest describes the binaries in dist as release of version.
func buildManifest(dist, version, commit, date string) ([]byte, error) {
	// os.Root confines file access to dist.
	root, err := os.OpenRoot(dist)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return nil, err
	}
	tag := tagOf(version)
	m := Manifest{
		Name:       "vpncraft",
		Version:    version,
		Tag:        tag,
		Prerelease: isPrerelease(version),
		Commit:     commit,
		Date:       date,
		Repository: repositoryURL,
		Assets:     []Asset{},
	}
	for _, e := range entries {
		match := assetPattern.FindStringSubmatch(e.Name())
		if match == nil || e.IsDir() {
			continue
		}
		sum, size, err := hashFile(root, e.Name())
		if err != nil {
			return nil, err
		}
		m.Assets = append(m.Assets, Asset{
			OS:     match[1],
			Arch:   match[2],
			File:   e.Name(),
			Size:   size,
			SHA256: sum,
			URL:    fmt.Sprintf("%s/releases/download/%s/%s", repositoryURL, tag, e.Name()),
		})
	}
	if len(m.Assets) == 0 {
		return nil, fmt.Errorf("no release binaries (vpncraft_<os>_<arch>) in %s", dist)
	}
	slices.SortFunc(m.Assets, func(a, b Asset) int { return strings.Compare(a.File, b.File) })

	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func hashFile(root *os.Root, name string) (string, int64, error) {
	f, err := root.Open(name)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}
