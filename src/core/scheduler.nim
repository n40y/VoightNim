## ===============================================================
## src/core/scheduler.nim
## 
## Ce fichier sert de Jitter et permet de mettre du hasard dans 
## les délais des requêtes.
## 
## Amplitude:
## 
## Délai = baseDelay + Aléatoire(-jitterRange, +jitterRange)
## 
## ===============================================================

import std/[asyncdispatch, random]
import ../prober # Permet de récupérer checkPort et DefaultTimeoutMs


# Introduit une pause asynchrone avec variation aléatoire
proc waitWithJitter*(baseDelayMs: int, jitterMs: int) {.async.} =
  if jitterMs <= 0:
    await sleepAsync(baseDelayMs)
    return

  let variation = rand(-jitterMs .. jitterMs)
  let finalDelay = max(0, baseDelayMs + variation)
  await sleepAsync(finalDelay)


# Mélange les ports, applique le jitter et distribue via le pool de workers.
proc prepareAndScan*(targetIP: string,
 ports: seq[int],
  concurrency: int,
   baseDelayMs: int,
    jitterMs: int,
     timeoutMs: int = DefaultTimeoutMs
     ): Future[seq[tuple[port: int, isOpen: bool]]] {.async.} =

  var shuffledPorts = ports
  shuffle(shuffledPorts)

  var results: seq[tuple[port: int, isOpen: bool]] = @[]
  var currentIdx = 0

  # Définition du worker de scan
  proc worker() {.async.} =
    while currentIdx < shuffledPorts.len:
        # Sélection synchrone du port avant tout point de suspension (async safe)
      let port = shuffledPorts[currentIdx]
      currentIdx += 1
      
      # Application de la signature temporelle aléatoire
      await waitWithJitter(baseDelayMs, jitterMs)
      
      # Exécution du scan de port existant
      let res = await checkPort(targetIP, port, timeoutMs)
      results.add(res)

  # Lancement du pool de workers asynchrones
  var workers = newSeq[Future[void]]()
  let poolSize = min(concurrency, shuffledPorts.len)
  
  for i in 0 ..< poolSize:
    workers.add(worker())
    
  # Attente de la fin de toutes les sondes
  await all(workers)
  return results