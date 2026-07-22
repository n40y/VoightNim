## ===============================================================================
## src/prober.nim
## ===============================================================================

import std/[asyncdispatch, asyncnet, nativesockets, strutils, monotimes, times]
when defined(ssl):
  import std/net

when not defined(windows):
  import std/posix

import ./fingerprint/types
import ./fingerprint/utils

const DefaultTimeoutMs* = 800

# --- Calibration de la concurrence selon la limite système -----------------

proc getMaxConcurrency*(requested: int): int =
  when defined(windows):
    result = min(requested, 1000)
  else:
    var limit: RLimit
    if getrlimit(RLIMIT_NOFILE, limit) == 0:
      let safeCeiling = int(limit.rlim_cur) - 50
      result = min(requested, max(safeCeiling, 1))
    else:
      result = min(requested, 100)

# --- Logique de scan de ports asynchrone ------------------------------------

proc checkPort*(targetIP: string, port: int, timeoutMs: int = DefaultTimeoutMs): Future[tuple[port: int, isOpen: bool]] {.async.} =
  let socket = newAsyncSocket()
  try:
    let connFut = socket.connect(targetIP, Port(port))
    if await withTimeout(connFut, timeoutMs):
      try: socket.close() except: discard
      return (port: port, isOpen: true)
    else:
      try: socket.close() except: discard
      return (port: port, isOpen: false)
  except CatchableError:
    try: socket.close() except: discard
    return (port: port, isOpen: false)

proc scanChunk*(targetIP: string, ports: seq[int], concurrency: int, timeoutMs: int = DefaultTimeoutMs): Future[seq[tuple[port: int, isOpen: bool]]] {.async.} =
  result = @[]
  var i = 0
  while i < ports.len:
    var futures: seq[Future[tuple[port: int, isOpen: bool]]] = @[]
    let chunkEnd = min(ports.len, i + concurrency)
    for j in i ..< chunkEnd:
      futures.add(checkPort(targetIP, ports[j], timeoutMs))
    let chunkResults = await all(futures)
    result.add(chunkResults)
    i += concurrency

## Conversion binaire sécurisée de seq[byte] vers string sans arrêt sur 0x00
proc bytesToString(bytes: seq[byte]): string =
  if bytes.len == 0: return ""
  result = newString(bytes.len)
  for i in 0 ..< bytes.len:
    result[i] = char(bytes[i])

## Exécution de la Sonde
proc executeProbe*(targetIP: string, port: int, probe: ServiceProbe, timeoutMs: int): Future[string] {.async.} =
  var socket = newAsyncSocket()
  var banner = ""
  
  try:
    # 1. Enveloppement TLS asynchrone AVANT connexion
    if probe.transport == trTLS:
      when defined(ssl):
        let ctx = newContext(verifyMode = CVerifyNone)
        wrapSocket(ctx, socket)
      else:
        return ""

    # 2. Connexion asynchrone (inclut le handshake SSL si TLS)
    let connFut = socket.connect(targetIP, Port(port))
    if not (await withTimeout(connFut, timeoutMs)):
      try: socket.close() except: discard
      return ""

    # 3. Récriture dynamique du payload HTTP
    var payload = probe.payload
    if probe.probeType == ptHTTP:
      let httpPayloadStr = "GET / HTTP/1.1\r\nHost: " & targetIP & "\r\nUser-Agent: VoightNim/1.0\r\nConnection: close\r\n\r\n"
      payload = toBytes(httpPayloadStr)

    # 4. Envoi du payload binaire (s'il existe)
    if payload.len > 0:
      let payloadStr = bytesToString(payload)
      await socket.send(payloadStr)

    # 5. Première lecture : on utilise le vrai timeoutMs de la sonde
    let firstRecvFut = socket.recv(4096)
    if await withTimeout(firstRecvFut, timeoutMs):
      let chunk = firstRecvFut.read()
      if chunk.len > 0:
        banner.add(chunk)
      else:
        try: socket.close() except: discard
        return ""
    else:
      try: socket.close() except: discard
      return ""

    # 6. Boucle de lecture pour vider le reste du buffer (timeout court pour le surplus)
    while banner.len < 32768:
      let recvFut = socket.recv(4096)
      if not (await withTimeout(recvFut, 50)):
        break
      let chunk = recvFut.read()
      if chunk.len == 0:
        break
      banner.add(chunk)

    try: socket.close() except: discard
    return banner

  except CatchableError:
    try: socket.close() except: discard
    return ""

proc grabBanner*(targetIP: string, port: int, probes: seq[ServiceProbe], timeoutMs: int = DefaultTimeoutMs): Future[string] {.async.} =
  let p16 = uint16(port)
  var banner = ""

  # 1. Priorité aux sondes assignées à ce port
  for probe in probes:
    if p16 in probe.ports:
      let probeTimeout = if probe.timeoutMs > 0: probe.timeoutMs else: timeoutMs
      banner = await executeProbe(targetIP, port, probe, probeTimeout)
      if banner.len > 0: 
        return banner

  # 2. Test passif rapide (timeout réduit à 400ms max)
  let passiveProbe = ServiceProbe(
    probeType: ptNull, 
    name: "passive", 
    payload: @[], 
    transport: trTCP
  )
  banner = await executeProbe(targetIP, port, passiveProbe, min(timeoutMs, 400))
  if banner.len > 0: 
    return banner

  # 3. Fallback : Test rapide des autres sondes
  for probe in probes:
    if p16 notin probe.ports and probe.payload.len > 0:
      banner = await executeProbe(targetIP, port, probe, 250)
      if banner.len > 0: 
        return banner

  return ""