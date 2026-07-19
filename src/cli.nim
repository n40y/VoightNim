## =======================================================
## src/cli.nim 
## =======================================================

import docopt
import std/[strutils]


let doc* = """
Usage:
    voightnim <target> port <ports> [--syn] [-s <speed>] [-d <delay>] [-j <jitter>] [-v] [--json]
    voightnim <target> [--syn] [-s <speed>] [-d <delay>] [-j <jitter>] [-v] [--json]
    voightnim --passive [--timeout <ms>]

Options:
    --syn          Enable high-performance stealth SYN scanning (requires root/admin)
    -s <speed>     Max concurrent connections / packet rate [default: 10]
    -d <delay>     Base stealth delay between requests in ms [default: 100]
    -j <jitter>    Max random jitter added/subtracted in ms [default: 30]
    --passive       Enable passive listening mode (no packets sent)
    --timeout <ms>  Timeout for passive mode in milliseconds [default: 0]
    -v, --verbose  Show all traffic
    --json         Output results as JSON (disables colored output)
    -h, --help     Show commands options
"""

proc printBanner*() =
    echo "\x1B[36mVoightNim Scanner"
    echo "██╗   ██╗  ██████╗  ██╗  ██████╗  ██╗  ██╗ ████████╗ ███╗   ██╗ ██╗ ███╗   ███╗ "
    echo "██║   ██║ ██╔═══██╗ ██║ ██╔════╝  ██║  ██║ ╚══██╔══╝ ████╗  ██║ ██║ ████╗ ████║ "
    echo "██║   ██║ ██║   ██║ ██║ ██║  ███╗ ███████║    ██║    ██╔██╗ ██║ ██║ ██╔████╔██║ "
    echo "╚██╗ ██╔╝ ██║   ██║ ██║ ██║   ██║ ██╔══██║    ██║    ██║╚██╗██║ ██║ ██║╚██╔╝██║ "
    echo " ╚████╔╝  ╚██████╔╝ ██║ ╚██████╔╝ ██║  ██║    ██║    ██║ ╚████║ ██║ ██║ ╚═╝ ██║ "
    echo "  ╚═══╝    ╚═════╝  ╚═╝  ╚═════╝  ╚═╝  ╚═╝    ╚═╝    ╚═╝  ╚═══╝ ╚═╝ ╚═╝     ╚═╝ v0.1\x1B[0m\n"


proc parsePorts*(portsRaw: string): seq[int] =
    ## Parse les chaînes de type "80", "80,443" ou "21-25,80"
    result = @[]
    for part in portsRaw.split(','):
        let trimmed = part.strip()
        if trimmed.contains('-'):
            let rangeParts = trimmed.split('-')
            if rangeParts.len == 2:
                try:
                    let startPort = parseInt(rangeParts[0].strip())
                    let endPort = parseInt(rangeParts[1].strip())
                    for port in startPort .. endPort:
                        result.add(port)
                except ValueError:
                    discard
        else:
            try:
                result.add(parseInt(trimmed))
            except ValueError:
                discard


proc parseCLI*(): auto =
    try:
        return docopt(doc, help = false, version = "VoightNim v0.1")
    except DocoptExit:
        let yellow = "\x1B[33m"
        let green = "\x1B[32m"
        let reset = "\x1B[0m"
        
        printBanner()
        echo yellow & "Usage:" & reset
        echo "    voightnim <target> port <ports> [--syn] [-s <speed>] [-v] [--json]"
        echo "    voightnim <target> [--syn] [-s <speed>] [-v] [--json]"
        echo "    voightnim --passive [--timeout <ms>]\n"
        echo green & "Options:" & reset
        echo "     --syn          Enable high-performance stealth SYN scanning (requires root/admin)"
        echo "    -s <speed>     Select threads [default: 10]"
        echo "    -d <delay>     Base stealth delay between requests in ms [default: 100]"
        echo "    -j <jitter>    Max random jitter added/subtracted in ms [default: 30]"
        echo "    --passive       Enable passive listening mode (no packets sent)"
        echo "    --timeout <ms>  Timeout for passive mode in milliseconds [default: 0]"
        echo "    -v, --verbose  Show all traffic"
        echo "    --json         Output results as JSON (disables colored output)"
        echo "    -h, --help     Show commands options"
        quit(0)