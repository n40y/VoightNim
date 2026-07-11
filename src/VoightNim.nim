# src/VoightNim.nim
import cli
import docopt
import std/[terminal, strutils, asyncdispatch, json, os]
import prober
import signatures
import topports

type ScanResult = tuple[port: int, isOpen: bool, service: string]

proc main() =
  let args = parseCLI()
  let jsonMode = args["--json"]

  let target = $args["<target>"]
  let speed = parseInt($args["-s"])

  if not jsonMode:
    styledEcho fgCyan, "[-] Target detected  : ", fgWhite, styleBright, target
    styledEcho fgCyan, "[-] Concurrent conns : ", fgWhite, styleBright, $speed

  var portsToScan: seq[int]
  if args["port"]:
    let portsRaw = $args["<ports>"]
    portsToScan = parsePorts(portsRaw)
    if not jsonMode:
      styledEcho fgGreen, "[+] Ports to scan    : ", fgWhite, styleBright, portsRaw
  else:
    portsToScan = commonPorts
    if not jsonMode:
      styledEcho fgYellow, "[!] No port specified; using common ports list (",
                 fgWhite, styleBright, $commonPorts.len, fgYellow, " ports)."

  if portsToScan.len == 0:
    if jsonMode:
      echo $(%*{"error": "No valid ports to scan"})
    else:
      styledEcho fgRed, "[!] No valid ports to scan. Check your <ports> argument."
    quit(1)

  # Le coeur du scan : scanRange gère la concurrence (calibrée par ulimit) et le batching
  let rawResults = scanRange(target, portsToScan, speed)

  # Une seule collecte de résultats (avec identification de service),
  # réutilisée ensuite pour l'affichage texte OU JSON — pas de double scan.
  var scanResults: seq[ScanResult] = @[]
  var openCount = 0
  for r in rawResults:
    if r.isOpen:
      inc openCount
      let service = waitFor identifyService(target, r.port)
      scanResults.add (r.port, true, service)
    else:
      scanResults.add (r.port, false, "")

  if jsonMode:
    var jsonArr = newJArray()
    for sr in scanResults:
      var entry = %*{"port": sr.port, "open": sr.isOpen}
      if sr.isOpen:
        entry["service"] = %sr.service
      jsonArr.add entry

    let output = %*{
      "target": target,
      "speed": speed,
      "portsScanned": portsToScan.len,
      "openCount": openCount,
      "results": jsonArr
    }
    echo $output
  else:
    for sr in scanResults:
      if sr.isOpen:
        styledEcho fgGreen, "[+] Port ", fgWhite, styleBright, $sr.port, fgGreen, styleBright, " is OPEN  ",
                   fgWhite, "-> ", styleBright, sr.service
      elif args["--verbose"]:
        styledEcho fgRed, "[-] Port ", fgWhite, $sr.port, fgRed, " is CLOSED"

    styledEcho fgCyan, "[-] Scan complete    : ", fgWhite, styleBright, $openCount,
               fgCyan, " open port(s) found on ", fgWhite, styleBright, $portsToScan.len, " scanned."

if isMainModule:
  let jsonRequested = "--json" in commandLineParams()
  if not jsonRequested:
    printBanner()
  main()
