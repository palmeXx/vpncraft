<p align="center">
  <img src="docs/vpn_craft_logo_v3_256.png" alt="vpncraft logo" width="256">
</p>

<h1 align="center">vpncraft</h1>

<p align="center"><strong>Warcraft III LAN games over a VPN.</strong></p>

Warcraft III finds LAN games via UDP broadcasts on port 6112. Broadcasts do not
cross VPN tunnels such as Tailscale, NetBird or WireGuard, so players on the
same VPN cannot see each other's games. vpncraft fixes that:

- **relay mode** captures local Warcraft III broadcasts and forwards them as
  unicast to a group of VPN peers. Games show up in the LAN list as if everybody
  were on the same network.
- **sniff mode** logs and decodes Warcraft III LAN packets (text log and raw dump)
  for troubleshooting.

It ships as a single static binary for Linux, macOS and Windows (amd64/arm64),
with an interactive terminal UI and a headless mode for scripts and services.

> All IP addresses, interface names, paths and outputs in this README are
> fictional examples.

---

## Contents

- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Running vpncraft](#running-vpncraft)
  - [Interactive TUI](#interactive-tui)
  - [Headless mode](#headless-mode)
  - [Privileges](#privileges)
- [Command line flags](#command-line-flags)
- [Configuration file](#configuration-file)
- [Peer discovery and scan range](#peer-discovery-and-scan-range)
- [Typical setup with friends](#typical-setup-with-friends)
- [Troubleshooting](#troubleshooting)
- [Building from source](#building-from-source)
- [Contributing](#contributing)
  - [Release process](#release-process)
- [Platform notes](#platform-notes)

---

## How it works

```
 Player A (hosts a game)                         Player B (joins)
 ┌──────────────────────┐                        ┌──────────────────────┐
 │ Warcraft III         │                        │ Warcraft III         │
 │   │ UDP broadcast    │                        │   ▲                  │
 │   ▼ :6112            │       VPN tunnel       │   │ UDP :6112        │
 │ vpncraft relay ──────┼──── unicast :6112 ────►│   │                  │
 └──────────────────────┘                        └──────────────────────┘
```

- vpncraft **passively captures** UDP traffic on port 6112. It does not bind the
  port, so it runs next to Warcraft III on the same machine.
- Only Warcraft III packets (W3GS protocol, first byte `0xF7`) are relayed.
- Each packet is re-sent to every peer in the peer group at `<peer>:6112` with
  **source port 6112**, so replies (e.g. game info for a game search) reach the
  local game directly.
- Packets coming from or going to a peer are ignored, which prevents relay loops.
- Capturing and sending use raw sockets, so vpncraft needs root/Administrator
  rights (see [Privileges](#privileges)). It is pure Go without cgo or libpcap/Npcap.

---

## Requirements

- Linux, macOS or Windows on amd64 or arm64
- A working VPN between the players (Tailscale, NetBird, WireGuard, ...)
- Root (Linux/macOS) or Administrator (Windows) rights to run it
- Warcraft III LAN traffic allowed through local firewalls on the VPN interface
  (UDP 6112 for discovery, TCP 6112 to join a hosted game)

---

## Installation

### Option 1: Prebuilt binary (recommended)

Download the binary for your platform from the
[GitHub releases](https://github.com/palmeXx/vpncraft/releases) page:

| Platform              | File                           |
|-----------------------|--------------------------------|
| Linux x86-64          | `vpncraft_linux_amd64`         |
| Linux ARM64           | `vpncraft_linux_arm64`         |
| macOS Intel           | `vpncraft_darwin_amd64`        |
| macOS Apple Silicon   | `vpncraft_darwin_arm64`        |
| Windows x86-64        | `vpncraft_windows_amd64.exe`   |
| Windows ARM64         | `vpncraft_windows_arm64.exe`   |

Each release also contains `SHA256SUMS` and a `manifest.json` that describes
the release for scripts and update checks (version, tag, commit, build date and,
per binary, OS, architecture, size, SHA-256 and download URL):

```json
{
  "name": "vpncraft",
  "version": "0.1.0",
  "tag": "v0.1.0",
  "prerelease": false,
  "commit": "abc1234",
  "date": "2026-01-01T00:00:00Z",
  "repository": "https://github.com/palmeXx/vpncraft",
  "assets": [
    {
      "os": "linux",
      "arch": "amd64",
      "file": "vpncraft_linux_amd64",
      "size": 5853936,
      "sha256": "…",
      "url": "https://github.com/palmeXx/vpncraft/releases/download/v0.1.0/vpncraft_linux_amd64"
    }
  ]
}
```

The manifest of the newest release is always at
`https://github.com/palmeXx/vpncraft/releases/latest/download/manifest.json`.

**Linux / macOS**

```sh
# verify the download (optional)
sha256sum -c SHA256SUMS --ignore-missing      # Linux
shasum -a 256 -c SHA256SUMS --ignore-missing  # macOS

# install
chmod +x vpncraft_linux_amd64
sudo mv vpncraft_linux_amd64 /usr/local/bin/vpncraft
```

On macOS, binaries downloaded with a browser are quarantined by Gatekeeper.
Since the binary is not signed, remove the quarantine attribute before the first run:

```sh
xattr -d com.apple.quarantine vpncraft_darwin_arm64
```

**Windows: install with a desktop shortcut**

The following PowerShell commands install vpncraft for the current user and
create a desktop shortcut that opens the TUI in a terminal window. The
installation itself needs no administrator rights. Open *PowerShell* (normal
user) and run:

```powershell
# Install location (per user) and release asset (use vpncraft_windows_arm64.exe on ARM devices)
$dir   = "$env:LOCALAPPDATA\Programs\vpncraft"
$asset = "vpncraft_windows_amd64.exe"

# Download the latest release
New-Item -ItemType Directory -Force -Path $dir | Out-Null
Invoke-WebRequest -Uri "https://github.com/palmeXx/vpncraft/releases/latest/download/$asset" -OutFile "$dir\vpncraft.exe"
Unblock-File "$dir\vpncraft.exe"

# Desktop shortcut: double-click opens the TUI in a terminal window
$shell = New-Object -ComObject WScript.Shell
$lnk = $shell.CreateShortcut("$([Environment]::GetFolderPath('Desktop'))\vpncraft.lnk")
$lnk.TargetPath       = "$dir\vpncraft.exe"
$lnk.WorkingDirectory = $dir
$lnk.Description      = "vpncraft - Warcraft III LAN over VPN"
$lnk.Save()
```

Then enable administrator rights for the shortcut, which vpncraft needs for
capturing and sending:

1. Right-click **vpncraft** on the desktop → **Properties**.
2. On the **Shortcut** tab, click **Advanced…**.
3. Check **Run as administrator** → **OK** → **OK**.

Double-clicking the shortcut now shows the UAC prompt and opens the TUI in a
terminal window. When you quit vpncraft, the window closes.

Notes:

- **Verify the download (optional):** compare the hash with the release's `SHA256SUMS`:
  `Get-FileHash "$env:LOCALAPPDATA\Programs\vpncraft\vpncraft.exe" -Algorithm SHA256`
- **Windows Terminal:** on Windows 11 the window opens in Windows Terminal if it
  is set as the default terminal application (*Settings → System → For developers
  → Terminal*). Otherwise the classic console host is used.
- **Configuration:** the elevated process uses your normal user profile if your
  account is an administrator, so the config file stays at
  `%USERPROFILE%\.config\vpncraft\config.yaml`.
- **Git Bash / mintty / MSYS2:** these terminals are not Windows consoles, so
  vpncraft cannot detect a terminal there and runs headless instead of
  starting the TUI. Use PowerShell, cmd or Windows Terminal for the TUI, or pass
  flags / `-headless` to run headless on purpose.
- **Window closes immediately:** start vpncraft from an elevated terminal to
  read the error message:
  `& "$env:LOCALAPPDATA\Programs\vpncraft\vpncraft.exe"`
- **Update:** run the `Invoke-WebRequest` and `Unblock-File` lines again.
  The shortcut keeps working.
- **Uninstall:** delete `%LOCALAPPDATA%\Programs\vpncraft` and the desktop shortcut.

**Windows: manual installation**

Download `vpncraft_windows_amd64.exe` from the releases page, rename it to
`vpncraft.exe` and put it into a folder of your choice, e.g. `C:\Tools\vpncraft\`.
Optionally add that folder to `PATH`. Then create the shortcut by hand
(right-click the file → *Show more options* → *Create shortcut*) and enable
*Run as administrator* as described above.

### Option 2: `go install`

With Go 1.27 or newer:

```sh
go install github.com/palmeXx/vpncraft/cmd/vpncraft@latest
```

Binaries built this way report version `dev` and commit `unknown`, because the
build metadata is injected by the Makefile (see [Building from source](#building-from-source)).

### Option 3: Build from source

See [Building from source](#building-from-source).

### Check the installation

```sh
vpncraft -version
# [*] vpncraft 0.1.0 (commit abc1234, built 2026-01-01T00:00:00Z, linux/amd64, go1.27.4)
```

The commit hash of the build is printed every time vpncraft starts.

---

## Quick start

1. Connect your VPN.
2. Start the TUI with admin rights:
   ```sh
   sudo vpncraft            # Linux / macOS
   ```
   On Windows, double-click the **vpncraft** desktop shortcut
   ([installation](#option-1-prebuilt-binary-recommended)), or run `vpncraft.exe`
   in a terminal opened **as Administrator**.
3. Select your VPN interface (highlighted as `VPN`) and press `enter`.
4. Press `s`, choose a scan range, and wait for the scan to finish.
5. Select the peers with `space`, then press `enter` to add them to the peer group.
6. Press `m` to switch to **relay** mode and `w` to save the configuration.
7. Press `enter` to start relaying, then start Warcraft III and open the LAN screen.

---

## Running vpncraft

vpncraft has two ways of running:

| Invocation                                       | Result                        |
|--------------------------------------------------|-------------------------------|
| `vpncraft` (no flags, in a terminal)             | interactive TUI               |
| `vpncraft -config <file>` (in a terminal)        | interactive TUI with that file |
| `vpncraft` with any other flag                   | headless                      |
| `vpncraft -headless`                             | headless, configuration file only |
| not attached to a terminal (service, pipe, cron) | headless                      |

### Interactive TUI

The TUI has four screens.

**1. Interfaces**: lists network interfaces. Likely VPN interfaces are listed
first and highlighted with a `VPN` tag and the reason they were detected
(interface name, an address in `100.64.0.0/10`, or a point-to-point link).
Interfaces without an IPv4 address are hidden by default.

| Key           | Action                                  |
|---------------|-----------------------------------------|
| `↑`/`↓`, `k`/`j` | move                                 |
| `enter`       | select interface                        |
| `h`           | show/hide interfaces without IPv4       |
| `r`           | reload interfaces                       |
| `q`, `esc`    | quit                                    |

**2. Overview**: interface, mode, config file path and the peer group.
Host names are resolved via reverse DNS where available (e.g. Tailscale MagicDNS).

| Key           | Action                                  |
|---------------|-----------------------------------------|
| `enter`       | start the selected mode                 |
| `m`, `tab`    | toggle mode (sniff / relay)             |
| `s`           | scan for peers (opens the scan range selection) |
| `a`           | add a peer by IPv4 address              |
| `d`, `delete` | remove the selected peer                |
| `w`           | write the configuration file            |
| `↑`/`↓`       | move in the peer group                  |
| `esc`, `i`    | back to interface selection             |
| `q`           | quit                                    |

**3. Scan range and scan**: choose the range to ping. See
[Peer discovery and scan range](#peer-discovery-and-scan-range).

| Key           | Action                                  |
|---------------|-----------------------------------------|
| `enter`       | scan the selected range                 |
| `c`           | enter a custom CIDR range               |
| `esc`         | back / cancel a running scan            |

After the scan, responding hosts are listed. Peers already in the group are pre-selected.

| Key           | Action                                  |
|---------------|-----------------------------------------|
| `space`       | toggle host                             |
| `a`           | select all / none                       |
| `enter`       | apply: add selected hosts, remove deselected group members |
| `esc`         | discard results                         |

**4. Running**: live output of the relay or sniffer. `esc` stops it and returns
to the overview. In the TUI, relay mode uses exactly the peer group you see; it
does not scan automatically.

`ctrl+c` quits from any screen.

### Headless mode

Headless mode reads the configuration file, applies command line flags on top
and runs until `Ctrl+C` / `SIGTERM`.

```sh
# relay with the peer group from the config file
sudo vpncraft -headless

# relay on utun4, scan 100.64.0.0/24 for peers, plus two fixed peers
sudo vpncraft -m relay -i utun4 -scan-network 100.64.0.0/24 -peers 100.64.0.2,100.64.0.3

# relay to fixed peers only, no scan
sudo vpncraft -m relay -i wt0 -no-scan -peers 100.64.0.2

# sniff Warcraft III traffic on all interfaces into custom files
sudo vpncraft -m sniff -i all -log-file /tmp/wc3.log -bin-file /tmp/wc3.bin
```

In relay mode with `scan.enabled: true` (default), vpncraft first ping-scans the
interface network and adds responding hosts to the peer group, then starts relaying.

**Exit codes**

| Code | Meaning                                                    |
|------|------------------------------------------------------------|
| `0`  | stopped normally (`Ctrl+C`) or `-version`/`-h`             |
| `1`  | runtime error (e.g. missing privileges, socket errors)     |
| `2`  | invalid flags or configuration, missing or unknown interface |

### Privileges

vpncraft needs raw socket access for capturing, sending and ping scans.

**Linux**: run as root:

```sh
sudo vpncraft
```

Alternatively grant the `CAP_NET_RAW` capability to the binary, which is what
packet and raw sockets require (see `packet(7)` and `raw(7)`). This setup is not
covered by the test suite.

```sh
sudo setcap cap_net_raw+ep /usr/local/bin/vpncraft
vpncraft
```

**macOS**: run with `sudo` (capturing uses `/dev/bpf*`, which is root-only by default).

**Windows**: use the desktop shortcut with *Run as administrator* enabled
(see [Installation](#option-1-prebuilt-binary-recommended)), or start a terminal
(PowerShell, Windows Terminal, cmd) via *Run as administrator*.

> **Note:** under `sudo`, `~` refers to root's home directory. The TUI then reads
> and writes `/root/.config/...` (Linux) or `/var/root/.config/...` (macOS).
> To use your own configuration file, pass it explicitly:
> `sudo vpncraft -config ~/.config/vpncraft/config.yaml`

---

## Command line flags

Flags override values from the configuration file. Only flags you actually pass
take effect; everything else comes from the file or the built-in defaults.
Both `-flag` and `--flag` work.

| Flag | Config key | Default | Description |
|------|------------|---------|-------------|
| `-config <file>` | – | see [lookup order](#location-and-lookup-order) | Configuration file to use. The file must exist. |
| `-headless` | – | `false` | Run without TUI, using the configuration file only. |
| `-version` | – | – | Print version, commit and build date, then exit. |
| `-m`, `-mode <mode>` | `mode` | `sniff` | `sniff` logs packets, `relay` forwards broadcasts to peers. |
| `-i`, `-interface <name>` | `interface` | *none, required* | Network interface. Relay: VPN interface used for peer scans (capturing always covers all interfaces, because local games broadcast on the LAN). Sniff: capture interface, or `all`. |
| `-peers <ip,ip,...>` | `peers` | empty | Comma-separated IPv4 peer addresses. Replaces the peer group from the config file. Can be repeated. |
| `-no-scan` | `scan.enabled: false` | scan enabled | Relay mode: do not ping-scan for peers on startup. |
| `-scan-network <cidr>` | `scan.network` | detect | Explicit scan range, e.g. `100.64.12.0/24`. At most `/16`. Not limited by `-scan-min-prefix`. |
| `-scan-min-prefix <n>` | `scan.min_prefix` | `24` | Largest *detected* network that is scanned automatically, as prefix length (`16`–`32`). |
| `-scan-rate <n>` | `scan.rate` | `5000` | Maximum ICMP echo requests per second. |
| `-scan-timeout <dur>` | `scan.timeout` | `1s` | Time to wait for replies after the last request (Go duration, e.g. `500ms`, `2s`). |
| `-log-file <path>` | `sniff.log_file` | `wc3_broadcasts.log` | Sniff mode: decoded text log (appended). |
| `-bin-file <path>` | `sniff.bin_file` | `wc3_packets.bin` | Sniff mode: raw payload dump (appended). |
| `-h`, `-help` | – | – | Show help, including the config file lookup paths. |

The interface has no default on purpose. If it is missing or does not exist,
vpncraft lists the likely VPN interfaces and explains how to configure one:

```
[!] Error: no interface set: specify it with -i <name> or 'interface:' in the config file
[*] Likely VPN interfaces:
      utun4        100.64.0.10/32       (name)
[*] Or create the config file /home/user/.config/vpncraft/config.yaml, e.g.:

      interface: utun4

    or pass it with -i utun4, or run `vpncraft` in a terminal to choose it in the TUI.
```

---

## Configuration file

### Location and lookup order

The first existing file wins:

1. the file given with `-config <file>`
2. `$XDG_CONFIG_HOME/vpncraft/config.yaml` (only if `XDG_CONFIG_HOME` is set to an absolute path)
3. `~/.config/vpncraft/config.yaml`

The same layout is used on every platform. On Windows, `~` is your user profile,
e.g. `C:\Users\<name>\.config\vpncraft\config.yaml`.

If no file exists, the built-in defaults are used. Pressing `w` in the TUI
writes the file given with `-config`, otherwise it creates the file (and its
directory) at the first of the two standard locations above.

### Validation

The file is validated on every start. vpncraft refuses to start (exit code `2`)
and names the file and the problem if:

- the file contains unknown keys (typos such as `modus:` are caught),
- `mode` is neither `sniff` nor `relay`,
- a peer is not an IPv4 address,
- `scan.rate` or `scan.timeout` is not positive,
- `scan.min_prefix` is outside `16`–`32`,
- `scan.network` is not IPv4 or larger than `/16`,
- `sniff.log_file` or `sniff.bin_file` is empty.

Peers are de-duplicated and sorted automatically. All keys are optional. Only
`interface` has to be set, either in the file or with `-i`, before running.

### Reference

```yaml
# Operation mode: sniff | relay
mode: relay

# Network interface (required here or via -i).
# Examples: wt0 (NetBird on Linux), tailscale0 (Tailscale on Linux),
# utun4 (macOS tunnels), wg0 (WireGuard). Sniff mode also accepts "all".
interface: wt0

# Static peer group: relay targets, IPv4 only.
# (Fictional example addresses.)
peers:
  - 100.64.0.2
  - 100.64.0.3

scan:
  # Relay mode (headless): ping-scan for peers on startup and add them to the group.
  enabled: true
  # ICMP echo requests per second.
  rate: 5000
  # Wait time for replies after the last request.
  timeout: 1s
  # Largest detected network that is scanned automatically (prefix length 16-32).
  min_prefix: 24
  # Explicit scan range, at most /16. "" = detect from the interface.
  network: ""

sniff:
  # Decoded text log, appended.
  log_file: wc3_broadcasts.log
  # Raw W3GS payloads, appended back to back.
  bin_file: wc3_packets.bin
```

A copy of this file is included as [`config.example.yaml`](config.example.yaml).

---

## Peer discovery and scan range

vpncraft finds peers with an ICMP ping sweep: one echo request per address,
paced at `scan.rate`, followed by `scan.timeout` of waiting for replies. Peers
must answer ping requests to be found. Peers can always be added manually.

### How the network is detected

1. If the interface address has a real netmask (smaller than `/32`), that
   network is used, e.g. `10.8.0.2/24` → `10.8.0.0/24`.
2. VPN tunnels often carry a `/32` address. vpncraft then reads the
   **routing table** and uses the most specific route through that interface that
   contains the local address. Default routes and host routes are ignored.
   Linux reads all routing tables via netlink (Tailscale uses a separate table),
   macOS uses the BSD routing socket and Windows uses `GetIpForwardTable2`.

What this yields depends on the VPN:

| VPN | Typical result | Scanned automatically (default limit `/24`)? |
|-----|----------------|------------------------------|
| WireGuard with a small network | interface mask, e.g. `/24` | yes |
| NetBird | `/16` (not verified) | no, choose a range |
| Tailscale | `100.64.0.0/10` (≈ 4.2 million addresses) | no, choose a range |

### Choosing the range

**TUI**: pressing `s` opens a range selection:

```
Select scan range  utun4, local IP 100.64.0.10
  100.64.0.0/10     4194302 hosts   detected (routing table)  – too large (max /16)
▸ 100.64.0.0/16       65534 hosts   /16 around local IP
  100.64.0.0/24         254 hosts   /24 around local IP
```

- **Configured**: `scan.network` from the configuration, if set (preselected)
- **Detected**: the detected network (preselected if it is small enough)
- **`/16` and `/24` around the local IP**: offered when smaller than the detected network
- **Custom** (`c`): any IPv4 CIDR up to `/16`

Ranges larger than `/16` are shown but cannot be selected. The chosen range is
stored as `scan.network`, so `w` saves it. Choosing the detected network clears
`scan.network`, i.e. "detect automatically".

**Headless**: `scan.network` / `-scan-network` is used if set. Otherwise the
detected network is scanned if it is not larger than `scan.min_prefix`;
if it is larger, the scan is skipped with a hint and the static peers are used.

**Scan duration**: roughly `hosts / rate + timeout`. A `/24` takes about a
second, a `/16` about 14 seconds at the default rate.

---

## Typical setup with friends

1. Everybody joins the same VPN.
2. **Every player runs vpncraft in relay mode** with the other players in their
   peer group. This forwards hosted games to everybody and forwards game searches
   to the host.
3. The host's firewall must allow inbound **TCP 6112** on the VPN interface so
   others can join, and UDP 6112 for discovery.
4. Start Warcraft III and open *Local Area Network*. Games hosted by peers appear
   in the list.

To share a setup, commit a configuration file without personal data, or send a
one-liner such as:

```sh
sudo vpncraft -m relay -i tailscale0 -no-scan -peers 100.64.0.2,100.64.0.3
```

---

## Troubleshooting

| Symptom | Cause / Fix |
|---------|-------------|
| `Root/Admin privileges required` | Run with `sudo` or as Administrator (see [Privileges](#privileges)). |
| `no interface set` / `interface "..." not found` | Set `interface:` in the config or pass `-i`. The message lists likely VPN interfaces. |
| `Invalid configuration: config ...` | Fix the reported key; unknown keys are rejected. |
| TUI does not start, plain output instead | vpncraft is not attached to a terminal (e.g. Git Bash/mintty on Windows, pipes, services), or flags other than `-config` were passed. |
| `Peer scan skipped: network ... is larger than the scan limit` | Set `scan.network` / `-scan-network`, or pick a range in the TUI. |
| Scan finds no peers | Peers may block ICMP echo (ping). Add them manually with `a` or `-peers`. |
| Games are not listed | Check that the peer runs relay mode, both peer groups are correct, and UDP 6112 is not blocked on the VPN interface. Use sniff mode on both sides to see which packets arrive. |
| Joining a listed game fails | The host must allow inbound TCP 6112 on the VPN interface. |
| TUI saved the config to the wrong place | Under `sudo`, `~` is root's home; use `-config ~/.config/vpncraft/config.yaml`. |

**Sniff mode output** looks like this (data shortened):

```
[2026-01-02 03:04:05] Captured 4 bytes from 192.0.2.10:6112
Payload (Hex):
f7 2f 10 00
Decoded Message:
Host IP Address: 192.0.2.10
Packet ID: 0x2F | Declared Length: 16 bytes
ASCII Stream: ./..
------------------------------------------------------------
```

Game announcements (packet IDs `0x30`–`0x33`) additionally show the game name
and map.

---

## Building from source

Requirements: Go 1.27+, GNU Make, a POSIX shell. `golangci-lint` v2 is only needed for linting.

```sh
git clone https://github.com/palmeXx/vpncraft.git
cd vpncraft

make build          # host binary → bin/vpncraft
make build-all      # all platforms → dist/vpncraft_<os>_<arch>[.exe]
make checksums      # build-all + dist/SHA256SUMS
make manifest       # checksums + dist/manifest.json (all release assets)
```

All builds use `CGO_ENABLED=0`, so cross-compiling works from any host.
Windows binaries embed the logo as icon (shown in Explorer, the taskbar and the
desktop shortcut): `make build-windows` generates `cmd/vpncraft/rsrc_windows_*.syso`
from `docs/vpn_craft_logo_v3.png` with a pinned
[go-winres](https://github.com/tc-hib/go-winres), and the Go linker picks them up
automatically. The `.syso` files are generated, not committed; Linux and macOS
binaries have no icon.
Version, commit hash and build date are injected via `-ldflags -X` into
`internal/buildinfo`. The version comes from `version.json`, the commit is the
short hash of `HEAD` and the date the current UTC time. Override them with
`make build VERSION=1.2.3-dev`.

Run `make help` to list all targets:

| Target | Description |
|--------|-------------|
| `make check` | format check, `go vet` and `golangci-lint` for linux/darwin/windows, unit tests |
| `make vuln` | `govulncheck` (pinned version) for linux/darwin/windows |
| `make test` / `make test-race` | unit tests (race detector requires cgo) |
| `make cover` | coverage report (`coverage.html`) |
| `make test-integration` | integration tests; raw-socket tests are skipped without root |
| `make test-integration-privileged` | raw-socket integration tests via `sudo` |
| `make fuzz FUZZTIME=30s` | fuzz the packet parsers |
| `make build-linux` / `build-windows` / `build-darwin` | per-OS release binaries |
| `make winres` | generate the Windows icon resources from the logo (done by `build-windows`) |
| `make manifest` | all release assets: binaries, `SHA256SUMS`, `manifest.json` |
| `make release-check` | check `version.json` and `CHANGELOG.md` as next release (`BASE=origin/main`) |
| `make release-notes` | preview the release notes (`REF=v0.1.0` for an existing release) |
| `make run ARGS="-m relay -i wt0"` | build and run |
| `make clean` | remove `bin/`, `dist/`, coverage files, generated `.syso` files and legacy PyInstaller artifacts |

**CI** (GitHub Actions) runs on every pull request and every commit on `main`:
lint and `govulncheck` for Linux, macOS and Windows, tests on Linux, macOS and
Windows runners (including the raw-socket tests with root/Administrator rights)
and the release build. See [Release process](#release-process) for releases.

### Project layout

```
cmd/vpncraft/        CLI entry point: flags, config resolution, TUI vs. headless
internal/app/        sniff/relay orchestration, scan planning, host name lookup
internal/capture/    passive IPv4/UDP capture (AF_PACKET, /dev/bpf, SIO_RCVALL)
internal/discovery/  ICMP ping sweep
internal/netutil/    interfaces, VPN detection, routing table, host ranges
internal/relay/      W3GS relay and raw UDP forwarder (fixed source port)
internal/settings/   YAML configuration: load, validate, save
internal/sniff/      sniff mode logger
internal/tui/        Bubble Tea terminal UI
internal/wc3/        Warcraft III (W3GS) packet decoding
test/integration/    integration tests (build tag `integration`)
tools/release/       release helper: version check, release notes, manifest.json
```

---

## Contributing

Contributions are welcome: bug reports and ideas as
[issues](https://github.com/palmeXx/vpncraft/issues), changes as pull requests.
Every pull request to `main` is the next release, merging it publishes it.

1. For larger changes, open an issue first to agree on the approach.
2. Fork the repository and create a branch from `main`.
3. Make the change, add or update tests and run the checks:

   ```sh
   make check
   make vuln
   make test-integration-privileged   # raw-socket tests, asks for sudo
   ```

4. Decide if the pull request is a release:
   - **Changes of the tool** are released. Raise `version` in `version.json`
     and add a `CHANGELOG.md` section for it, see
     [Release process](#release-process). Check both with `make release-check`
     and preview the release notes with `make release-notes`.
   - **Other changes**, like the README, the workflows or only tests, are not
     released. Keep the version, the maintainer labels the pull request
     `no-release`. Only users with write access can set labels, mention it in
     the pull request.

   If you're unsure, ask in the pull request.
5. Open the pull request against `main`. The checks `Release check`, `Lint`,
   `Vulnerability check`, `Test (ubuntu-latest)`, `Test (macos-latest)`,
   `Test (windows-latest)` and `Build binaries` have to pass.
6. After the review, the maintainer merges the pull request, which creates the
   tag and the GitHub release automatically.

Use synthetic data only. Don't put real details of your network, like IP
addresses, host names or interface details, into tests, issues or shared logs.

### Release process

`version.json` is the single source of truth for the version:

```json
{
  "version": "0.2.0"
}
```

Versions follow [semantic versioning](https://semver.org/) without a `v`
(`0.2.0`, pre-releases like `0.2.0-rc.1`). Git tags carry a `v` (`v0.2.0`), as
Go modules require for `go install …@v0.2.0`.

1. **Pull request:** the workflow `Release check` requires that `version` is
   greater than on `main`, that the tag doesn't exist yet and that
   `CHANGELOG.md` has a section for it:

   ```markdown
   ## [0.2.0] - 2026-12-01

   ### Added

   - …
   ```

   Pull requests labeled `no-release` skip the check.
2. **Merge into `main`:** the workflow `Release` runs the full CI on the merged
   commit. If the tag `v<version>` doesn't exist yet, it then creates the tag on
   that commit and the GitHub release. Commits whose version already has a tag,
   e.g. `no-release` pull requests, are only tested.
3. **Release contents:**
   - **Assets:** the six binaries, `SHA256SUMS` and `manifest.json`
   - **Notes:** the `CHANGELOG.md` section of the version, followed by the
     commits since the previous tag and a compare link
   - **Pre-releases:** versions with a suffix (`-rc.1`) are marked as pre-release

A release can also be created by pushing a tag that matches `version.json`
(`git tag v0.2.0 && git push origin v0.2.0`), or by running the `Release`
workflow manually with an existing tag. That also updates the notes and assets
of an existing release.

---

## Platform notes

| | Linux | macOS | Windows |
|---|---|---|---|
| Capture | `AF_PACKET` with in-kernel BPF filter | `/dev/bpf*` with BPF filter | raw socket with `SIO_RCVALL` |
| Routing table | netlink (all tables) | routing socket | `GetIpForwardTable2` |
| Privileges | root or `CAP_NET_RAW` | root | Administrator |

The CI workflow runs unit and raw-socket integration tests on all three platforms.

- **Windows:** `SIO_RCVALL` cannot capture on the loopback interface, so relay
  mode captures on all other interfaces. It has not yet been verified on a real
  Windows machine that broadcasts sent by a local Warcraft III instance are
  captured this way. Feedback is welcome.
- **IPv4 only:** Warcraft III LAN discovery uses IPv4 broadcasts, so vpncraft
  handles IPv4 only.
