# src/prober.nim
#
# Compilation : nim c src/VoightNim.nim
# (pas besoin de --threads:on ici : asyncdispatch tourne sur un seul thread
# avec un event loop, contrairement à la version précédente basée sur threadpool)

import std/[asyncdispatch, asyncnet, nativesockets, strutils]

import fingerprint/types
import fingerprint/utils

when not defined(windows):
    import std/posix

const DefaultTimeoutMs* = 800

# --- Calibration de la concurrence selon la limite système -----------------

proc getMaxConcurrency*(requested: int): int =
    ## Ajuste `requested` à la baisse si la limite système de descripteurs
    ## de fichiers (ulimit -n) ne permet pas d'ouvrir autant de connexions.
    when defined(windows):
        # Windows ne fonctionne pas sur le même modèle d'ulimit POSIX ;
        # on applique un plafond prudent plutôt qu'une détection réelle.
        result = min(requested, 1000)
    else:
        var limit: RLimit
        if getrlimit(RLIMIT_NOFILE, limit) == 0:
            let safeCeiling = int(limit.rlim_cur) - 50  # marge pour stdin/stdout/stderr...
            result = min(requested, max(safeCeiling, 1))
        else:
            result = min(requested, 256)  # repli prudent si getrlimit échoue

# --- Scan d'un port unique (async) ------------------------------------------

proc scanPortAsync*(targetIP: string, port: int, timeoutMs: int = DefaultTimeoutMs): Future[bool] {.async.} =
    ## Tente une connexion TCP non-bloquante sur (targetIP, port).
    ## Retourne true si le port est ouvert, false si fermé/filtré/timeout.
    let socket = newAsyncSocket(Domain.AF_INET, SockType.SOCK_STREAM, Protocol.IPPROTO_TCP, buffered = false)
    let connectFut = socket.connect(targetIP, Port(port))

    # withTimeout renvoie true si connectFut s'est terminé (succès OU échec)
    # dans le délai imparti, false si le délai est dépassé (encore en attente)
    let completed = await withTimeout(connectFut, timeoutMs)

    if not completed:
        # Timeout : on referme le socket pour couper court à la tentative
        socket.close()
        return false

    socket.close()

    if connectFut.failed:
        # Connexion refusée / erreur réseau : on "consomme" l'erreur pour
        # éviter qu'elle remonte comme exception non gérée
        discard connectFut.error
        return false

    return true

# --- Parsing de la liste de ports (ex: "80,443,8000-8010") -----------------

proc parsePorts*(portsRaw: string): seq[int] =
    result = @[]
    for item in portsRaw.split(','):
        let cleaned = item.strip()
        if cleaned == "": continue

        if '-' in cleaned:
            let parts = cleaned.split('-')
            if parts.len == 2:
                try:
                    let startPort = parseInt(parts[0].strip())
                    let endPort = parseInt(parts[1].strip())
                    for p in startPort..endPort:
                        if p > 0 and p <= 65535:
                            result.add(p)
                except ValueError:
                    discard
        else:
            try:
                let p = parseInt(cleaned)
                if p > 0 and p <= 65535:
                    result.add(p)
            except ValueError:
                discard

# --- Scan concurrent d'une liste de ports (event loop, pas de threads) -----

proc scanChunk(targetIP: string, ports: seq[int], timeoutMs: int): Future[seq[bool]] {.async.} =
    ## Lance toutes les connexions du chunk en parallèle sur l'event loop
    ## et attend qu'elles se terminent toutes (succès, échec ou timeout).
    var futures: seq[Future[bool]] = @[]
    for p in ports:
        futures.add scanPortAsync(targetIP, p, timeoutMs)
    result = await all(futures)

proc scanRange*(targetIP: string, ports: seq[int], speed: int,
                 timeoutMs: int = DefaultTimeoutMs): seq[tuple[port: int, isOpen: bool]] =
    ## Scanne `ports` par paquets, calibrés selon `speed` ET la limite système.
    ## `all()` préserve l'ordre : results[i] correspond bien à chunkPorts[i].
    result = @[]
    let effectiveSpeed = getMaxConcurrency(speed)
    var i = 0
    while i < ports.len:
        let chunkEnd = min(i + effectiveSpeed, ports.len)
        let chunkPorts = ports[i ..< chunkEnd]
        let results = waitFor scanChunk(targetIP, chunkPorts, timeoutMs)

        for idx, p in chunkPorts:
            result.add (p, results[idx])

        i = chunkEnd

# --- Récupération de bannière sur un port confirmé ouvert -------------------

proc grabBanner*(
    targetIP: string,
    port: int,
    probes: seq[ServiceProbe],
    timeoutMs: int = DefaultTimeoutMs
): Future[string] {.async.} =
    ## À appeler uniquement sur un port déjà confirmé ouvert par scanRange.
    ## Ouvre une NOUVELLE connexion dédiée (celle du scan initial est fermée).
    ## Essaie chaque probe dans l'ordre jusqu'à obtenir une réponse non vide ;
    ## ne fait AUCUNE analyse de la bannière (c'est le rôle de fingerprint/engine).
    let socket = newAsyncSocket(Domain.AF_INET, SockType.SOCK_STREAM, Protocol.IPPROTO_TCP, buffered = false)
    let connectFut = socket.connect(targetIP, Port(port))

    if not await withTimeout(connectFut, timeoutMs):
        socket.close()
        return ""

    if connectFut.failed:
        discard connectFut.error
        socket.close()
        return ""

    result = ""

    for probe in probes:
        try:
            if probe.payload.len > 0:
                await socket.send(toString(probe.payload))

            let recvFut = socket.recv(4096)
            if not await withTimeout(recvFut, probe.timeoutMs):
                continue  # rien reçu à temps sur cette sonde, on tente la suivante

            let banner = recvFut.read()
            if banner.len > 0:
                result = banner
                break
        except OSError:
            break  # socket cassé côté distant, inutile d'insister

    socket.close()
