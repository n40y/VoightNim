##=================================================
##
## src/VoightNim.nim
##
##=================================================

import docopt
import std/[terminal, strutils, asyncdispatch, json]

import cli
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
    printBanner()
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
      styledEcho fgYellow, "[!] No port specified; using common ports list"

  let maxConcurrency = getMaxConcurrency(speed)

  # 1. Scan initial des ports en parallèle
  let rawResults = waitFor scanChunk(target, portsToScan, maxConcurrency)

  # 2. Filtrage des ports ouverts
  var openPorts: seq[int] = @[]
  for r in rawResults:
    if r.isOpen:
      openPorts.add(r.port)

  var scanResults: seq[ScanResult] = @[]

  if openPorts.len > 0:
    if not jsonMode:
      styledEcho fgYellow, "[!] Gathering banners concurrently for ", fgWhite, styleBright, $openPorts.len, fgYellow, " ports..."

    # 3. Lancement simultané du banner grabbing sur tous les ports ouverts
    var bannerFutures: seq[Future[string]] = @[]
    let allProbes = getAllProbes()
    for port in openPorts:
      bannerFutures.add(grabBanner(target, port, allProbes, DefaultTimeoutMs))

    # 4. Attente asynchrone globale (Résolution du goulot d'étranglement)
    let banners = waitFor all(bannerFutures)

    # 5. Analyse des signatures avec le moteur de fingerprinting
    for i, port in openPorts:
      let banner = banners[i]
      var matchedServices: seq[Fingerprint] = @[]
      var matchedOs: seq[OsFingerprint] = @[]
      
      for probe in allProbes:
        if uint16(port) in probe.ports or probe.ports.len == 0:
          let sFp = detectAll(banner, probe)
          if sFp.len > 0:
            for f in sFp: matchedServices.add(f)
          
          let oFp = detectAllOs(banner, probe)
          if oFp.len > 0:
            for o in oFp: matchedOs.add(o)

      scanResults.add((
        port: port,
        isOpen: true,
        banner: banner,
        services: matchedServices,
        osResults: matchedOs
      ))

  # 6. Rendu des résultats (JSON ou Console stylisée)
  if jsonMode:
    var jsonArr = newJArray()
    for sr in scanResults:
      var obj = newJObject()
      obj["port"] = %sr.port
      obj["isOpen"] = %sr.isOpen
      obj["banner"] = %sr.banner
      
      var servicesArr = newJArray()
      for fp in sr.services:
        var sObj = newJObject()
        sObj["product"] = %fp.info.product
        sObj["version"] = %fp.version
        sObj["confidence"] = %int(fp.confidence)
        servicesArr.add(sObj)
      obj["services"] = servicesArr

      var osArr = newJArray()
      for osfp in sr.osResults:
        var oObj = newJObject()
        oObj["name"] = %osfp.info.name
        oObj["version"] = %osfp.version
        oObj["confidence"] = %int(osfp.confidence)
        osArr.add(oObj)
      obj["os"] = osArr
      
      jsonArr.add(obj)
    echo $jsonArr
  else:
    for sr in scanResults:
      styledEcho fgGreen, "[+] Port ", fgWhite, styleBright, $sr.port, fgGreen, " is OPEN"
      var hasInfo = false

      for fp in sr.services:
        if fp.confidence >= 50:
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
          let endIdx = min(100, rawPreview.len)
          styledEcho "      ", fgYellow, "└─ unknown : ", fgWhite,
                     "raw banner: ", rawPreview[0 ..< endIdx]
        else:
          styledEcho "      ", fgYellow, "└─ unknown : ", fgWhite, "no banner received"

    if args["--verbose"]:
      for r in rawResults:
        if not r.isOpen:
          styledEcho fgRed, "[-] Port ", fgWhite, $r.port, fgRed, " is CLOSED"

  if not jsonMode:
    styledEcho fgCyan, "[-] Scan complete    : ", fgWhite, styleBright, "VoightNim finished successfully."

when isMainModule:
  main()