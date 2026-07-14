#===============================================================================
# src/prober.nim
#
# Compilation : nim c src/VoightNim.nim
# Pas besoin de --threads:on   car    asyncdispatch   tourne sur un seul thread
# avec un event loop, contrairement à la version précédente basée sur threadpool
#=================================================================================

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
    ## Retourne true si le port est ouvert, false si fermé/filtré/timeout/erreur.
    let socket = newAsyncSocket(Domain.AF_INET, SockType.SOCK_STREAM, Protocol.IPPROTO_TCP, buffered = false)

    try:
        let connectFut = socket.connect(targetIP, Port(port))

        # withTimeout renvoie true si connectFut s'est terminé (succès OU échec)
        # dans le délai imparti, false si le délai est dépassé (encore en attente)
        let completed = await withTimeout(connectFut, timeoutMs)

        if not completed:
            # Timeout : le connect() est encore EN VOL côté OS (cas typique d'un
            # port filtré, sans RST). On ferme quand même tout de suite :
            # asyncnet.close() désenregistre le fd du sélecteur AVANT de le
            # fermer réellement, donc même si l'OS recycle ce numéro de fd pour
            # un socket créé juste après, l'event loop ne peut plus jamais
            # rattacher un évènement tardif à l'ancien Future (il n'est plus
            # dans la table du sélecteur). Sans ça, chaque port filtré fuit un
            # descripteur pendant potentiellement des dizaines de secondes
            # (le vrai timeout de connect() côté noyau) : sur un grand range,
            # ça épuise `ulimit -n` chunk après chunk, bien avant la fin du scan.
            try:
                socket.close()
            except CatchableError:
                discard
            return false

        socket.close()

        if connectFut.failed:
            # Connexion refusée / erreur réseau : on "consomme" l'erreur pour
            # éviter qu'elle remonte comme exception non gérée
            discard connectFut.error
            return false

        return true

    except CatchableError:
        # Filet de sécurité : QUOI QU'IL ARRIVE, une erreur réseau sur un port
        # (refus de connexion, reset, hôte injoignable, etc.) ne doit jamais
        # remonter comme exception non gérée -- ça ferait planter tout le scan
        # via all()/waitFor, qui propage l'échec d'un seul port à l'ensemble
        # du chunk. On traite simplement le port comme fermé.
        try:
            socket.close()
        except CatchableError:
            discard
        return false

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

proc scanRange*(targetIP: string, ports: seq[int], speed: int, timeoutMs: int = DefaultTimeoutMs): seq[tuple[port: int, isOpen: bool]] =
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

proc tryProbe(targetIP: string, port: int, probe: ServiceProbe, timeoutMs: int): Future[string] {.async.} =
    ## Essaie UNE sonde sur UNE connexion dédiée, neuve. Ne jamais réutiliser
    ## une connexion entre deux sondes différentes : si la première n'obtient
    ## rien, son payload (ou son absence) a quand même pu être vu par le
    ## service distant, qui peut désynchroniser ou fermer la session avant
    ## que la sonde suivante n'ait sa chance (c'est très net avec des
    ## protocoles binaires à préfixe de longueur comme Kerberos/SMB : un
    ## payload étranger fait attendre au serveur une trame géante qui
    ## n'arrivera jamais).
    let socket = newAsyncSocket(Domain.AF_INET, SockType.SOCK_STREAM, Protocol.IPPROTO_TCP, buffered = false)
    try:
        let connectFut = socket.connect(targetIP, Port(port))
        if not await withTimeout(connectFut, timeoutMs):
            socket.close()
            return ""
        if connectFut.failed:
            discard connectFut.error
            socket.close()
            return ""

        if probe.payload.len > 0:
            await socket.send(toString(probe.payload))

        let recvFut = socket.recv(4096)
        if not await withTimeout(recvFut, probe.timeoutMs):
            socket.close()
            return ""
        if recvFut.failed:
            discard recvFut.error
            socket.close()
            return ""

        result = recvFut.read()
        socket.close()
    except CatchableError:
        try: socket.close()
        except CatchableError: discard
        result = ""

proc grabBanner*(targetIP: string, port: int, probes: seq[ServiceProbe], timeoutMs: int = DefaultTimeoutMs): Future[string] {.async.} =
    ## À appeler uniquement sur un port déjà confirmé ouvert par scanRange.
    ## Ne retient QUE les sondes dont `ports` contient le port scanné (c'est
    ## tout l'intérêt de ce champ) ; si aucune sonde n'est spécifique à ce
    ## port, retombe sur une sonde passive (payload vide) pour au moins
    ## capter une bannière spontanée (services qui parlent en premier).
    ## Ne fait AUCUNE analyse de la bannière (c'est le rôle de fingerprint/engine).
    let p16 = uint16(port)
    var candidates: seq[ServiceProbe] = @[]
    for probe in probes:
        if p16 in probe.ports:
            candidates.add probe

    if candidates.len == 0:
        candidates.add ServiceProbe(
            probeType: ptNull, name: "passive", payload: @[],
            ports: @[], transport: trTCP, timeoutMs: timeoutMs
        )

    result = ""
    for probe in candidates:
        let banner = await tryProbe(targetIP, port, probe, timeoutMs)
        if banner.len > 0:
            result = banner
            break
