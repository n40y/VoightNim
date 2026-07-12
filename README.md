# VoightNim

![License](https://img.shields.io/badge/License-MIT-blue?style=flat)
![Nim](https://img.shields.io/badge/Nim-2.2.10-ffe953?style=flat&logo=nim&logoColor=black)
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
- **Service fingerprinting on multiple protocols** — grabs banners on open ports and matches them against an embedded signature database (HTTP server headers, SSH, FTP, SMTP, Redis) using a pure-Nim regex engine (no PCRE/C dependency)
- **Stacked, multi-result detection (unlike a single-verdict scanner)** — a single banner can surface *several* independent findings at once (e.g. web server + runtime + framework + OS), instead of collapsing to one guess per port
- **OS fingerprinting from banner hints** — infers the underlying OS (Ubuntu, Debian, CentOS, RHEL, Fedora, Windows) from clues leaked by other services (e.g. `Server: Apache/2.4.41 (Ubuntu)`, IIS implying Windows), surfaced independently from the service detection
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

| Path | Responsibility |
|------|-----------------|
| `VoightNim.nim` | Point d'entrée principal (orchestration scan + fingerprinting + affichage) |
| `cli.nim` | Gestion des arguments CLI (docopt) |
| `prober.nim` | Scan des ports et récupération de bannière (async, sans threads) |
| `topports.nim` | Liste des ports courants |

```
src/
├── VoightNim.nim
├── cli.nim
├── prober.nim
├── topports.nim
│
├── fingerprint/            # Moteur de fingerprinting
│   ├── engine.nim          # API haut niveau : detect, detectAll, detectOs, detectAllOs
│   ├── matcher.nim         # Applique les règles de signatures sur un banner
│   ├── types.nim           # Types partagés (ServiceId, OsId, Fingerprint, OsFingerprint...)
│   ├── services.nim        # Base de connaissances des services (getService)
│   ├── osCatalog.nim       # Base de connaissances des OS (getOs)
│   ├── registry.nim        # Registre des sondes (getAllProbes)
│   └── utils.nim           # Fonctions utilitaires (conversion bytes/string, split headers...)
│
├── probes/                 # Une sonde par protocole (connexion + payload uniquement)
│   ├── http.nim             # appelle signatures/http/init.nim + signatures/os/init.nim
│   ├── ssh.nim               # appelle signatures/ssh/init.nim + signatures/os/init.nim
│   ├── ftp.nim               # appelle signatures/ftp/init.nim
│   ├── smtp.nim              # appelle signatures/smtp/init.nim
│   └── redis.nim             # appelle signatures/redis/init.nim
│
└── signatures/              # Règles de détection, organisées par protocole/axe
    ├── http/
    │   ├── init.nim          # Agrège toutes les catégories ci-dessous
    │   ├── webservers.nim    # Nginx, Apache, Caddy, IIS, Traefik, Envoy...
    │   ├── runtimes.nim      # PHP, ASP.NET
    │   ├── frameworks.nim    # Express, Laravel, Django, Flask
    │   └── monitoring.nim    # Grafana, Prometheus, Elasticsearch/Kibana
    ├── ssh/
    │   ├── init.nim
    │   └── servers.nim       # OpenSSH, libssh, Dropbear, Cisco SSH, SunSSH
    ├── ftp/
    │   ├── init.nim
    │   └── servers.nim       # vsftpd, ProFTPD, FileZilla, Pure-FTPd, Microsoft FTP
    ├── smtp/
    │   ├── init.nim
    │   └── servers.nim       # Postfix, Exim, Microsoft Exchange, Sendmail
    ├── redis/
    │   ├── init.nim
    │   └── servers.nim       # Redis
    └── os/
        ├── init.nim
        ├── linux.nim         # Ubuntu, Debian, CentOS, RHEL, Fedora
        └── windows.nim       # Windows (via IIS, ASP.NET, en-tête Server)
```

## Legal disclaimer

This tool is intended strictly for authorized security testing, CTF environments, and personal lab use. Scanning systems you do not own or do not have explicit written permission to test may be illegal in your jurisdiction. The author assumes no liability for misuse.

## Roadmap / next steps

- [ ] **True nmap-parity top-1000 port list** — derive a statistically-ranked list from the real `nmap-services` data file instead of the current curated ~150-port list
- [ ] **Expand the signature database** — more services (databases: MySQL/PostgreSQL/MongoDB handshake banners, RDP, SNMP), more OS versions and families (FreeBSD, OpenBSD, macOS signals)
- [ ] **SYN scan mode** — raw-socket half-open scanning (`SOCK_RAW`) as a faster, stealthier alternative to full TCP connect scans; requires elevated privileges and has limited support on Windows
- [ ] **Unit tests** — validate `parsePorts`, `getMaxConcurrency`, and the matcher/engine layer against known inputs; integration tests against local mock services (e.g. `python -m http.server`, a local SSH daemon)
- [ ] **UDP scanning support** — currently TCP-only
- [ ] **Adaptive timeout** — adjust per-probe timeout based on observed RTT instead of a fixed value
- [ ] **Confidence-based deduplication** — when several rules match the same service, keep the highest-confidence result instead of returning every match
- [ ] **Portfolio polish** — terminal screenshots/recordings, a short write-up of the design decisions (why async over threads, why a pure-Nim regex engine, why the probe/signature/engine split), and a GitHub Pages entry alongside the other projects