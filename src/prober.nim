#===============================================================================
# src/prober.nim
#
# Compilation : nim c src/VoightNim.nim
# Pas besoin de --threads:on car asyncdispatch tourne sur un seul thread
# avec un event loop.
#=================================================================================

import std/[asyncdispatch, asyncnet, nativesockets, strutils, monotimes, times]
when defined(ssl):
    import std/net

when not defined(windows):
    import std/posix

import ./fingerprint/types
import ./fingerprint/utils
import ./fingerprint/proberegistry
import ./fingerprint/services


const DefaultTimeoutMs* = 800

proc probePortExhaustive*(ip: string, port: Port): async Task[ServiceInfo] =
  # Par défaut, le service est inconnu
  result = getService(sidUnknown)

  # Récupérer toutes les sondes chargées dans le registre (RDP, SMB, HTTP...)
  let allProbes = getAllRegisteredProbes()

  for probe in allProbes:
    var socket = newAsyncSocket()
    try:
      # 1. Connexion fraîche pour chaque protocole
      await socket.connect(ip, port, timeout = 1000)
      
      # 2. Envoi du payload spécifique de la sonde (si défini)
      if probe.payload.len > 0:
        await socket.send(probe.payload)
      
      # 3. Lecture de la réponse avec un timeout strict
      let response = await socket.recv(2048, timeout = 1500)
      
      # 4. Si on a une réponse, on la passe aux regex de CETTE sonde
      if response.len > 0:
        for matchRule in probe.matches:
          if response.contains(matchRule.pattern): # Ta logique de match regex
            socket.close()
            return getService(matchRule.service) # Bingo !
            
    except OSError, TimeoutError:
      discard # le port a drop ou n'a pas répondu à ce payload
    finally:
      if not socket.isClosed():
        socket.close()
  
  return getService(sidUnknown)


# --- Calibration de la concurrence selon la limite système -----------------

proc getMaxConcurrency*(requested: int): int =
    ## Ajuste `requested` à la baisse si la limite système de descripteurs
    ## de fichiers (ulimit -n) ne permet pas d'ouvrir autant de connexions.
    when defined(windows):
        result = min(requested, 1000)
    else:
        var limit: RLimit
        if getrlimit(RLIMIT_NOFILE, limit) == 0:
            let safeCeiling = int(limit.rlim_cur) - 50  # marge pour les descripteurs standards
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


# --- Récupération des bannières applicatives (Mutualisée) -------------------

proc readFromSocket(socket: AsyncSocket, timeoutMs: int): Future[string] {.async.} =
    var banner = ""
    let start = getMonoTime()
    while true:
        let elapsed = (getMonoTime() - start).inMilliseconds
        if elapsed >= timeoutMs:
            break
        
        let recvFut = socket.recv(1024)
        if await withTimeout(recvFut, max(1, int(timeoutMs - elapsed))):
            if recvFut.failed: break
            let chunk = recvFut.read()
            if chunk.len == 0: break
            banner.add(chunk)
            if banner.len > 32768: break
        else:
            break
    return banner


## Exécution de la Sonde
proc executeProbe*(targetIP: string, port: int, probe: ServiceProbe, timeoutMs: int): Future[string] {.async.} =
  var socket = newAsyncSocket()
  var banner = ""
  
  try:
    # Connexion asynchrone avec timeout
    let connFut = socket.connect(targetIP, Port(port))
    if not (await withTimeout(connFut, timeoutMs)):
      socket.close()
      return ""

    # 1. Gestion du chiffrement TLS (compilation avec -d:ssl requise)
    if probe.transport == trTLS:
      when defined(ssl):
        let ctx = newContext(verifyMode = CVerifyNone)
        # On passe targetIP pour que le SNI (Server Name Indication) fonctionne
        ctx.wrapConnectedSocket(socket, handshakeAsClient, targetIP)
      else:
        socket.close()
        return ""

    # 2. Récriture dynamique du payload (ex: injection de l'IP cible dans le Host HTTP)
    var payload = probe.payload
    if probe.probeType == ptHTTP: #
      let httpPayloadStr = "GET / HTTP/1.1\r\nHost: " & targetIP & "\r\nUser-Agent: VoightNim/1.0\r\nConnection: close\r\n\r\n"
      payload = toBytes(httpPayloadStr) #

    # 3. Gestion Server Speaks First vs Client Speaks First
    if payload.len > 0:
      # Client Speaks First : on envoie le payload immédiatement
      await socket.send(toString(payload)) #
    else:
      # Server Speaks First : on attend d'abord la bannière spontanée
      let recvFut = socket.recv(1024)
      if await withTimeout(recvFut, timeoutMs):
        let chunk = recvFut.read()
        if chunk.len > 0:
          banner.add(chunk)
      else:
        socket.close()
        return ""

    # 4. Boucle de lecture standard pour consommer le reste du buffer
    while banner.len < 32768:
      let recvFut = socket.recv(4096)
      # Si on a déjà des données, on n'attend pas inutilement le timeout complet
      let currentTimeout = if banner.len > 0: 50 else: timeoutMs
      if not (await withTimeout(recvFut, currentTimeout)):
        break
      let chunk = recvFut.read()
      if chunk.len == 0:
        break
      banner.add(chunk)

    socket.close()
    return banner

  except CatchableError:
    try: socket.close() except: discard
    return ""


proc grabBanner*(targetIP: string, port: int, probes: seq[ServiceProbe], timeoutMs: int = DefaultTimeoutMs): Future[string] {.async.} =
  ## Interroge un port ouvert en cascade avec une certitude absolue :
  ## 1. Sondes associées spécifiquement au port (Gain de temps si port standard).
  ## 2. Sonde passive (Server Speaks First : SSH, FTP...).
  ## 3. Stratégie Exhaustive : Test de TOUTES les sondes actives du système.
  let p16 = uint16(port)
  var banner = ""

  # 1. Priorité aux sondes officiellement assignées à ce port
  for probe in probes:
    if p16 in probe.ports:
      banner = await executeProbe(targetIP, port, probe, timeoutMs)
      if banner.len > 0: 
        return banner

  # 2. Fallback 1 : Mode passif si le port est inconnu
  let passiveProbe = ServiceProbe(
    probeType: ptNull, 
    name: "passive", 
    payload: @[], 
    transport: trTCP
  )
  banner = await executeProbe(targetIP, port, passiveProbe, timeoutMs)
  if banner.len > 0: 
    return banner

  # 3. Fallback 2 : STRATÉGIE EXHAUSTIVE (Sûre à 100%)
  # On parcourt absolument toutes les sondes chargées dans le moteur
  for probe in probes:
    # On évite de ré-exécuter celles qui ont déjà échoué à l'étape 1
    # Et on ne teste que les sondes qui ont un payload actif (Client-First)
    if p16 notin probe.ports and probe.payload.len > 0:
      banner = await executeProbe(targetIP, port, probe, timeoutMs)
      if banner.len > 0: 
        return banner

  return ""