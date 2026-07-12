# src/cli.nim
import docopt

let doc* = """
Usage:
    voightnim <target> port <ports> [-s <speed>] [-v] [--json]
    voightnim <target> [-s <speed>] [-v] [--json]

Options:
    -s <speed>     Select threads [default: 10]
    -v, --verbose  Show all traffic
    --json         Output results as JSON (disables colored output)
    -h, --help     Show commands options
"""

proc printBanner*() =
    echo "\x1B[36mVoightNim"
    echo "██╗   ██╗  ██████╗  ██╗  ██████╗  ██╗  ██╗ ████████╗ ███╗   ██╗ ██╗ ███╗   ███╗ "
    echo "██║   ██║ ██╔═══██╗ ██║ ██╔════╝  ██║  ██║ ╚══██╔══╝ ████╗  ██║ ██║ ████╗ ████║ "
    echo "██║   ██║ ██║   ██║ ██║ ██║  ███╗ ███████║    ██║    ██╔██╗ ██║ ██║ ██╔████╔██║ "
    echo "╚██╗ ██╔╝ ██║   ██║ ██║ ██║   ██║ ██╔══██║    ██║    ██║╚██╗██║ ██║ ██║╚██╔╝██║ "
    echo " ╚████╔╝  ╚██████╔╝ ██║ ╚██████╔╝ ██║  ██║    ██║    ██║ ╚████║ ██║ ██║ ╚═╝ ██║ "
    echo "  ╚═══╝    ╚═════╝  ╚═╝  ╚═════╝  ╚═╝  ╚═╝    ╚═╝    ╚═╝  ╚═══╝ ╚═╝ ╚═╝     ╚═╝ v0.1\x1B[0m\n"

proc parseCLI*(): auto =
    try:
        return docopt(doc, help = false, version = "VoightNim v0.1")
    except DocoptExit:
        let yellow = "\x1B[33m"
        let green = "\x1B[32m"
        let reset = "\x1B[0m"
        
        printBanner()
        echo yellow & "Usage:" & reset
        echo "    voightnim <target> port <ports> [-s <speed>] [-v] [--json]"
        echo "    voightnim <target> [-s <speed>] [-v] [--json]\n"
        echo green & "Options:" & reset
        echo "    -s <speed>     Select threads [default: 10]"
        echo "    -v, --verbose  Show all traffic"
        echo "    --json         Output results as JSON (disables colored output)"
        echo "    -h, --help     Show commands options"
        quit(0)