# src/VoightNim.nim

import cli
import docopt
import std/[terminal, strutils, asyncdispatch, json, os]

import prober
import topports
import fingerprint/types
import fingerprint/registry
import fingerprint/engine


type ScanResult = tuple[
  port: int,
  isOpen: bool,
  banner: string,
  services: seq[Fingerprint],
  osResults: seq[OsFingerprint]
]

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

  # Liste des probes
  let allProbes = getAllProbes()

  # Scan des ports
  let rawResults = scanRange(target, portsToScan, speed)

  # Collecte des résultats
  var scanResults: seq[ScanResult] = @[]
  var openCount = 0

  for r in rawResults:
    if r.isOpen:
      inc openCount

      var banner = ""
      var services: seq[Fingerprint] = @[]
      var osResults: seq[OsFingerprint] = @[]

      try:
        banner = waitFor grabBanner(target, r.port, allProbes)

        if banner.len > 0:
          for probe in allProbes:
            services.add engine.detectAll(banner, probe)
            osResults.add engine.detectAllOs(banner, probe)
      except CatchableError as e:
        if not jsonMode and args["--verbose"]:
          styledEcho fgRed, "[!] Port ", $r.port, " : erreur pendant l'analyse (", e.msg, ")"

      scanResults.add (r.port, true, banner, services, osResults)
    else:
      scanResults.add (r.port, false, "", @[], @[])

  # === AFFICHAGE JSON ===
  if jsonMode:
    var jsonArr = newJArray()
    for sr in scanResults:
      var entry = %*{"port": sr.port, "open": sr.isOpen}

      if sr.isOpen:
        var servicesArr = newJArray()
        for fp in sr.services:
          servicesArr.add %*{
            "product": fp.info.product,
            "vendor": fp.info.vendor,
            "version": fp.version,
            "confidence": fp.confidence
          }
        entry["services"] = servicesArr

        var osArr = newJArray()
        for osfp in sr.osResults:
          osArr.add %*{
            "name": osfp.info.name,
            "version": osfp.version,
            "confidence": osfp.confidence
          }
        entry["os"] = osArr

      jsonArr.add entry

    let output = %*{
      "target": target,
      "speed": speed,
      "portsScanned": portsToScan.len,
      "openCount": openCount,
      "results": jsonArr
    }
    echo $output

  # === AFFICHAGE TEXTE (amélioré) ===
  else:
    for sr in scanResults:
      if sr.isOpen:
        styledEcho fgGreen, "[+] Port ", fgWhite, styleBright, $sr.port,
                   fgGreen, styleBright, " is OPEN"

        var hasInfo = false

        for fp in sr.services:
          if fp.confidence >= 40:   # filtre de confiance
            hasInfo = true
            let versionStr = if fp.version.len > 0: " " & fp.version else: ""
            styledEcho "      ", fgCyan, "└─ service : ", fgWhite, styleBright,
                       fp.info.product, versionStr, fgWhite, " (", $fp.confidence, "%)"

        for osfp in sr.osResults:
          if osfp.confidence >= 40:
            hasInfo = true
            let versionStr = if osfp.version.len > 0: " " & osfp.version else: ""
            styledEcho "      ", fgMagenta, "└─ os      : ", fgWhite, styleBright,
                       osfp.info.name, versionStr, fgWhite, " (", $osfp.confidence, "%)"

        if not hasInfo:
          if sr.banner.len > 0:
            let rawPreview = sr.banner.strip().replace("\r\n", " ").replace("\n", " ")
            styledEcho "      ", fgYellow, "└─ unknown : ", fgWhite,
                       "raw banner: ", rawPreview[0 ..< min(100, rawPreview.len)]
          else:
            styledEcho "      ", fgYellow, "└─ unknown : ", fgWhite, "no banner received"

      elif args["--verbose"]:
        styledEcho fgRed, "[-] Port ", fgWhite, $sr.port, fgRed, " is CLOSED"

    styledEcho fgCyan, "[-] Scan complete    : ", fgWhite, styleBright, $openCount,
               fgCyan, " open port(s) found on ", fgWhite, styleBright, $portsToScan.len, " scanned."

if isMainModule:
  let jsonRequested = "--json" in commandLineParams()
  if not jsonRequested:
    printBanner()
  main()