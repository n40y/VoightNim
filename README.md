# VoightNim
![License](https://img.shields.io/badge/License-MIT-blue?style=flat)
![Nim](https://img.shields.io/badge/Nim-2.2.10-ffe953?style=for-the-badge&logo=nim&logoColor=black)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-informational?style=flat)

A lightweight, dependency-free TCP port scanner and service fingerprinter written in Nim, built from scratch as a learning project (no wrapping of `nmap`, `rustscan`, or any other external scanning tool).

```
██╗   ██╗  ██████╗  ██╗  ██████╗  ██╗  ██╗ ████████╗ ███╗   ██╗ ██╗ ███╗   ███╗
██║   ██║ ██╔═══██╗ ██║ ██╔════╝  ██║  ██║ ╚══██╔══╝ ████╗  ██║ ██║ ████╗ ████║
██║   ██║ ██║   ██║ ██║ ██║  ███╗ ███████║    ██║    ██╔██╗ ██║ ██║ ██╔████╔██║
╚██╗ ██╔╝ ██║   ██║ ██║ ██║   ██║ ██╔══██║    ██║    ██║╚██╗██║ ██║ ██║╚██╔╝██║
 ╚████╔╝  ╚██████╔╝ ██║ ╚██████╔╝ ██║  ██║    ██║    ██║ ╚████║ ██║ ██║ ╚═╝ ██║
  ╚═══╝    ╚═════╝  ╚═╝  ╚═════╝  ╚═╝  ╚═╝    ╚═╝    ╚═╝  ╚═══╝ ╚═╝ ╚═╝     ╚═╝
```

## Features

- **Async, event-loop based scanning** (`std/asyncdispatch` + `std/asyncnet`) — no OS thread-per-port overhead
- **Cross-platform** — runs on Windows, Linux, and macOS without platform-specific socket code
- **Automatic concurrency calibration** — reads the system's file descriptor limit (`ulimit -n` on POSIX) and caps concurrent connections accordingly, instead of relying on a blind, fixed thread count
- **Lightweight service fingerprinting** — grabs banners on open ports and matches them against a small embedded signature database (SSH, FTP, SMTP, HTTP server headers, common app frameworks) using a pure-Nim regex engine (no PCRE/C dependency)
- **JSON output mode** for scripting and piping into other tools
- **Custom port lists or ranges** (`22,80,443` or `8000-8010`), with a built-in list of common ports as a default

## Requirements

- [Nim](https://nim-lang.org/) 2.x
- [Nimble](https://github.com/nim-lang/nimble) (ships with Nim)
- Nimble packages: `docopt`, `regex`

## Installation

```bash
git clone https://github.com/n40y/VoightNim.git
cd VoightNim

nimble install docopt
nimble install regex
```

## Building

```bash
# Debug build
nim c src/VoightNim.nim

# Release build (recommended for actual scanning — significantly faster)
nim c -d:release src/VoightNim.nim
```

This produces `src/VoightNim` (or `src/VoightNim.exe` on Windows).

## Usage

```
voightnim <target> port <ports> [-s <speed>] [-v] [--json]
voightnim <target> [-s <speed>] [-v] [--json]

Options:
    -s <speed>     Max concurrent connections (auto-capped by system limits) [default: 10]
    -v, --verbose  Also display closed ports
    --json         Output results as JSON (disables colored/banner output)
    -h, --help     Show this help
```

### Examples

Scan specific ports:
```bash
./VoightNim 10.10.10.5 port 22,80,443,8080
```

Scan a port range with higher concurrency:
```bash
./VoightNim 10.10.10.5 port 1-1000 -s 200
```

No `port` argument scans the built-in common-ports list:
```bash
./VoightNim 10.10.10.5
```

Verbose mode (shows closed ports too):
```bash
./VoightNim 10.10.10.5 port 20-30 -v
```

Machine-readable output:
```bash
./VoightNim 10.10.10.5 port 22,80,443 --json | jq .
```

## Project structure

| File            | Responsibility                                                             |
|-----------------|-----------------------------------------------------------------------------|
| `cli.nim`       | CLI argument parsing (`docopt`) and banner display                         |
| `prober.nim`    | Async TCP connect scanning, port-range parsing, ulimit-based concurrency    |
| `signatures.nim`| Service probes (null probe + HTTP probe) and banner-matching signatures    |
| `topports.nim`  | Default list of commonly scanned ports                                     |
| `VoightNim.nim` | Entry point — wires everything together, formats text/JSON output          |

## Legal disclaimer

This tool is intended strictly for authorized security testing, CTF environments, and personal lab use. Scanning systems you do not own or do not have explicit written permission to test may be illegal in your jurisdiction. The author assumes no liability for misuse.

## Roadmap / next steps

- [ ] **True nmap-parity top-1000 port list** — derive a statistically-ranked list from the real `nmap-services` data file instead of the current curated ~150-port list
- [ ] **Expand the signature database** — more services (databases: MySQL/PostgreSQL/MongoDB handshake banners, RDP, SNMP), and basic OS fingerprint hints where possible without raw sockets
- [ ] **SYN scan mode** — raw-socket half-open scanning (`SOCK_RAW`) as a faster, stealthier alternative to full TCP connect scans; requires elevated privileges and has limited support on Windows
- [ ] **Unit tests** — validate `parsePorts`, `matchService`, and `getMaxConcurrency` against known inputs; integration tests against local mock services (e.g. `python -m http.server`, a local SSH daemon)
- [ ] **UDP scanning support** — currently TCP-only
- [ ] **Adaptive timeout** — adjust per-probe timeout based on observed RTT instead of a fixed value
- [ ] **Portfolio polish** — terminal screenshots/recordings, a short write-up of the design decisions (why async over threads, why a pure-Nim regex engine), and a GitHub Pages entry alongside the other projects
