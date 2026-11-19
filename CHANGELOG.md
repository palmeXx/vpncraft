# Changelog

All notable changes to vpncraft. The section of a version is the release note
of its GitHub release, see [Release process](README.md#release-process).

## [Unreleased]

## [0.1.0] - 2026-11-19

First release of the Go rewrite.

### Added

- Relay mode: passively captures local Warcraft III LAN broadcasts on UDP 6112
  and forwards them as unicast with source port 6112 to a peer group
- Sniff mode: decoded text log and raw dump of Warcraft III LAN packets
- Interactive TUI: interface selection with VPN detection, scan range
  selection, ICMP peer scan with host names, peer group editing, mode
  selection and saving to the configuration file
- Headless mode with flags and a validated YAML configuration file
  (`~/.config/vpncraft/config.yaml`)
- Scan range detection from the interface mask or the routing table, with a
  configurable limit
- Pure Go binaries for Linux, macOS and Windows (amd64, arm64), the commit
  hash is shown at every start
- Releases contain `SHA256SUMS` and a `manifest.json` with version, commit
  and checksums of all binaries
