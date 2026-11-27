# net-tool

<p align="center">
  <img src="docs/logo.svg" width="128" alt="net-tool logo" />
</p>

One single binary to **view and change this machine's network configuration** — interfaces, static IP / DHCP, DNS, Wi-Fi, the hosts file and the desktop proxy — on **macOS, Windows and Linux**, from the terminal (CLI) **and** from a small built-in Web UI. Written in Go, with a Vue 3 UI embedded in the same binary.

<p align="center">
  <a href="https://github.com/LinuxSuRen/net-tool">Repository</a> ·
  <a href="https://github.com/LinuxSuRen/net-tool/releases">Releases</a> ·
  <a href="https://github.com/LinuxSuRen/net-tool/issues">Issues</a> ·
  <a href="https://github.com/LinuxSuRen/net-tool/pulls">Pull Requests</a> ·
  <a href="LICENSE">License</a>
</p>

## Why

Every OS buries the same handful of settings behind different tools: `networksetup` on macOS, `netsh` / PowerShell on Windows, `nmcli` / `ip` on Linux. When you set up a lab machine, a robot host, or a freshly imaged laptop, you end up re-learning all three. net-tool gives the same commands and the same JSON the same way everywhere:

- `net-tool list` shows every interface with its IP, mode, gateway and DNS — one command on all three OSes;
- switch an interface to a static IP or back to DHCP without remembering `netsh interface ipv4 set address ...` syntax;
- set DNS servers per interface, join a Wi-Fi network, map a hostname in the hosts file, toggle the system proxy;
- `--dry-run` on every mutating command prints the exact system commands it would run;
- `net-tool serve` opens the same functionality in a browser, bound to `127.0.0.1` by default.

## Platform backends

| Capability | macOS | Windows | Linux |
|---|---|---|---|
| Interfaces, IP, gateway, DNS | `networksetup` + `ifconfig` | PowerShell `Get-Net*` (JSON) | NetworkManager (`nmcli`); read-only fallback via `ip` + `resolv.conf` |
| Static IP / DHCP | `networksetup -setmanual/-setdhcp` | `netsh interface ipv4` | `nmcli connection modify` |
| DNS servers | `networksetup -setdnsservers` | `netsh interface ipv4 set dnsservers` | `nmcli connection modify` |
| Wi-Fi scan / join | `airport -s` / `networksetup -setairportnetwork` | `netsh wlan show networks` / WLAN profile | `nmcli device wifi` |
| Wi-Fi hotspot (AP) | — | — | `nmcli connection` (AP mode + shared) |
| Hosts file | `/etc/hosts` | `%SystemRoot%\System32\drivers\etc\hosts` | `/etc/hosts` |
| Desktop proxy | per network service | WinINET registry (per user) | GNOME `gsettings` |

Linux without NetworkManager degrades to a read-only view; mutating commands report `unsupported` instead of guessing. Wi-Fi passwords passed on the `nmcli` command line are visible to other local users via `/proc` — prefer the prompt (`net-tool wifi connect <ssid>` without `--password`).

## Install

Prebuilt binaries for Linux, macOS and Windows (amd64 / arm64) are attached to [GitHub Releases](https://github.com/LinuxSuRen/net-tool/releases):

```bash
curl -fsSL https://github.com/LinuxSuRen/net-tool/releases/download/v0.2.0/net-tool-0.2.0-linux-amd64.tar.gz | tar xz
./net-tool list
```

With a Go toolchain (the web UI is embedded in releases; building from source needs Node for the frontend, see Development):

```bash
go install github.com/LinuxSuRen/net-tool@latest
```

## Quick start

```text
$ net-tool list
NAME          TYPE       STATE  MODE    ADDRESSES     GATEWAY      DNS
Wi-Fi         wifi       up     dhcp    192.168.1.5   192.168.1.1  192.168.1.1
Ethernet      ethernet   down   static  10.0.0.5      10.0.0.1
```

Switch an interface to a static IP (needs administrator privileges; `--dry-run` previews the exact system commands):

```bash
sudo net-tool set-ip Ethernet --ip 10.0.0.5 --mask 255.255.255.0 --gw 10.0.0.1
sudo net-tool set-ip Ethernet --dhcp          # and back
sudo net-tool set-ip Ethernet --ip 10.0.0.5 --dry-run
```

DNS per interface:

```bash
sudo net-tool set-dns Wi-Fi --servers 223.5.5.5,119.29.29.29
sudo net-tool set-dns Wi-Fi --auto           # back to DHCP-provided DNS
```

Wi-Fi:

```bash
net-tool wifi list
net-tool wifi connect "HomeNet"              # password prompt (input hidden)
net-tool wifi connect "HomeNet" --attempts 5 # retry a failed association up to 5 times
net-tool wifi disconnect                     # leave the current network
```

On Windows, net-tool detects WPA3-Personal networks (SAE with transition mode)
from the scan and waits until the adapter is really associated before reporting
success — `netsh wlan connect` alone returns success even when authentication
fails. A failed join is retried up to `--attempts` times (default 3); the API
accepts the same `attempts` field. The Web UI can remember a password per SSID
in the browser's `localStorage`; it is never sent to or stored by the server.

### Recovering a forgotten Wi-Fi password

The first choice is always the credential the OS already saved (no guessing):

```bash
net-tool wifi saved-password "HomeNet"        # Windows netsh export / Linux nmcli / macOS Keychain
```

`wifi recover` checks this saved credential automatically and finishes without
any guessing when it exists. Otherwise it uses a small candidate list; preview
it before any online attempt. Uploaded files are one password per line (or the
first CSV column), UTF-8 or GB18030; nothing is uploaded or written to disk by
the server.

```bash
net-tool wifi candidates "HomeNet" --wordlist pwds.txt --max 200
net-tool wifi recover "HomeNet" --wordlist pwds.txt --i-am-authorized
```

`recover` tries candidates **serially** with a short timeout (default 4 s) and
a pause (default 300 ms), stopping on the first match. It uses a temporary
connection/profile per attempt and removes it afterwards; the user's saved
profile is not overwritten. A successful match is shown in clear text. The
built-in list is deliberately small (about 30 common passwords plus SSID and
numeric variants, capped at 200 by default) — online guessing is slow and only
appropriate for networks you own or are authorized to test. macOS supports
reading the saved password but reports `unsupported` for online attempts,
because `networksetup` would overwrite the saved credential.

The Web UI exposes the same flow under Wi-Fi → 找回密码: read saved password,
preview/export candidates, authorize, then watch progress. Passwords and
candidate lists stay in memory in the browser and are cleared when the dialog
closes. The API jobs are `POST /api/wifi/password-audit`,
`GET/DELETE /api/wifi/password-audit/{id}` with masked progress.

Wi-Fi hotspot (AP mode, Linux via NetworkManager; macOS/Windows report
`unsupported` for now):

```bash
sudo net-tool wifi ap start "robot-ap" --password 'robot123456'   # WPA2, 2.4 GHz
sudo net-tool wifi ap start "robot-ap" --password 'robot123456' --band a --channel 36
sudo net-tool wifi ap start "robot-ap" --password ''              # open network
sudo net-tool wifi ap start "robot-ap" --password 'robot123456' --dry-run   # preview
sudo net-tool wifi ap stop
```

The hotspot shares this machine's connectivity (clients get DHCP from
NetworkManager's shared mode, gateway `10.42.0.1` unless `--gateway` says
otherwise). Starting replaces a leftover `net-tool-ap` connection of the same
name, so consecutive starts converge; stop removes the profile again.
Passwords on the command line are visible to other local users via `/proc` —
prefer the prompt (omit `--password`) or an empty value for an open network.

Hosts file — net-tool only edits a marked section, every other line is preserved byte-for-byte:

```bash
sudo net-tool hosts add 10.1.2.3 mydevice.local
net-tool hosts list
sudo net-tool hosts remove mydevice.local
```

System proxy (macOS: per network service; Windows: per user; Linux: GNOME session):

```bash
net-tool proxy get
sudo net-tool proxy set --http proxy.example.com:8080 --bypass "*.local,127.0.0.0/8"
sudo net-tool proxy off
```

Every command accepts `-o` (`--output`) for JSON output, e.g. `net-tool list -o json`.

## Web UI

```bash
sudo net-tool serve
# net-tool web UI: http://127.0.0.1:8190
```

The page offers the same four areas as the CLI — interfaces (edit IP/DNS in a dialog), Wi-Fi (scan, connect, disconnect and password recovery), hosts, proxy — in Chinese, and disables what the current platform backend cannot do. The selected tab, each list's name/type/status filters and the chosen sort column/direction are kept in the browser's `localStorage` and restored after a reload; use 重置 to clear a view's filters and sorting. Wi-Fi scanning retries briefly if Windows reports only the currently connected network right after a join, so the full list stays visible. The server binds `127.0.0.1` only; pass `--addr` deliberately if you really need another interface (changing network settings is a privileged operation — keep it local or tunnel it). If port `8190` is already taken, the next free consecutive port is tried automatically (up to 100) and the actual URL is printed; pass `--no-drift` to fail on a conflict instead. The REST API it serves is the same one the CLI capabilities map to, with `{"data": ...}` envelopes and stable error codes (`invalid_argument`, `not_found`, `unsupported`, `permission_denied`, `command_failed`).

## Development

```bash
make setup      # npm install for web/
make build      # build web (Vite) + embed + go build
make test       # go test + web build check
make lint       # go vet
```

Layout: `internal/netconf` holds the platform-agnostic model, the per-platform backends and pure parsers (table-driven tests run on every OS); `internal/api` the REST layer; `cmd` the cobra CLI; `web` the Vue 3 + Element Plus frontend whose build output is embedded via `go:embed`. CI runs Go tests on Linux/macOS/Windows plus a web build; releases are cut by goreleaser on tags.

## Contributing

Issues and PRs are welcome — one PR per kind of change, please. See [LICENSE](LICENSE) (Apache-2.0).
