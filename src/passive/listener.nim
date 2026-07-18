## =================================================
## src/passive/listener.nim
## =================================================

import std/[asyncnet, asyncdispatch, terminal, nativesockets]
import parser

# Worker asynchrone générique pour écouter sur un port UDP spécifique
proc listenProtocol(port: int, protoName: string, parserProc: proc(p: string): string, timeoutMs: int) {.async.} =
  let socket = newAsyncSocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
  socket.setSockOpt(OptReuseAddr, true)
  socket.setSockOpt(OptReusePort, true)
  
  try:
    socket.bindAddr(Port(port), "0.0.0.0")
  except OSError:
    styledEcho fgRed, "[!] Error: Unable to bind port ", $port, " (", protoName, "). Already in use?"
    return

  var totalTime = 0
  let checkInterval = 200 # ms

  while true:
    if timeoutMs > 0 and totalTime >= timeoutMs:
      break

    let fut = socket.recvFrom(1024)
    
    if await withTimeout(fut, checkInterval):
      let (data, address, _) = fut.read()
      if data.len > 0:
        let hostname = parserProc(data)
        if hostname.len > 0:
          styledEcho fgGreen, "[+] Passive (", protoName, "): ", fgWhite, styleBright, address, 
                     fgCyan, " is querying -> ", fgMagenta, styleBright, hostname
    else:
      if timeoutMs > 0:
        totalTime.inc(checkInterval)

# Lance l'écoute passive simultanée sur LLMNR, mDNS et NetBIOS
proc startPassiveListen*(timeoutMs: int = 0) {.async.} =
  styledEcho fgYellow, "[!] Passive Sniffer active (LLMNR, mDNS, NetBIOS). Press Ctrl+C to stop."
  styledEcho fgWhite, ("A0A0A0"), "[-] Listening on ports: UDP 5355, UDP 5353, UDP 137\n"

  # Association des fonctions de parsing de parser.nim
  let parseLlmnr = proc(p: string): string = parseDnsFormat(p)
  let parseMdns  = proc(p: string): string = parseDnsFormat(p)
  let parseNetbios = proc(p: string): string = parseNetbiosQuery(p)

  # Exécution concurrente des 3 workers dans la même boucle asynchrone
  await all([
    listenProtocol(5355, "LLMNR", parseLlmnr, timeoutMs),
    listenProtocol(5353, "mDNS", parseMdns, timeoutMs),
    listenProtocol(137, "NetBIOS", parseNetbios, timeoutMs)
  ])