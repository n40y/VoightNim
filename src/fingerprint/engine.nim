## =========================================================
## src/fingerprint/engine.nim
## =========================================================

import std/[options, tables]

import types
import matcher

# -----------------------------------------------------------------------------
# Axe "service"
# -----------------------------------------------------------------------------

proc detect*(banner: string, probe: ServiceProbe): Option[Fingerprint] =

  fingerprint(
    banner,
    probe
  )


proc dedupeByFamily(fps: seq[Fingerprint]): seq[Fingerprint] =
  ## Ne garde que le match de plus haute confiance par "famille" de service
  ## (ex: "Generic HTTP Server" et "Microsoft IIS" sont tous deux de la
  ## famille "Web Server" -> seul IIS, plus spécifique, est conservé).
  ## Deux familles différentes (ex: "Web Server" et "Runtime") restent
  ## affichées séparément : c'est le comportement "stacked" voulu.
  var bestByFamily = initTable[string, Fingerprint]()

  for fp in fps:
    let key = fp.info.family
    if key notin bestByFamily or fp.confidence > bestByFamily[key].confidence:
      bestByFamily[key] = fp

  result = @[]
  for fp in bestByFamily.values:
    result.add(fp)


proc detectAll*(banner: string, probe: ServiceProbe): seq[Fingerprint] =

  dedupeByFamily(
    fingerprintAll(
      banner,
      probe
    )
  )


proc detectBest*(banner: string, probes: seq[ServiceProbe]): Option[Fingerprint] =

  var best: Option[Fingerprint]

  for probe in probes:

    let fp = detect(
      banner,
      probe
    )

    if fp.isNone:
      continue

    if best.isNone:
      best = fp
      continue

    if fp.get.confidence > best.get.confidence:
      best = fp

  best

# -----------------------------------------------------------------------------
# Axe "OS"
# -----------------------------------------------------------------------------

proc detectOs*(banner: string, probe: ServiceProbe): Option[OsFingerprint] =

  fingerprintOs(
    banner,
    probe
  )


proc dedupeOs(fps: seq[OsFingerprint]): seq[OsFingerprint] =
  ## Même principe que dedupeByFamily, mais sur l'identité de l'OS
  ## (OsId) : plusieurs règles peuvent indiquer "Windows" indépendamment
  ## (en-tête IIS, en-tête ASP.NET...) ; on ne garde que la plus fiable.
  var bestById = initTable[OsId, OsFingerprint]()

  for fp in fps:
    let key = fp.info.id
    if key notin bestById or fp.confidence > bestById[key].confidence:
      bestById[key] = fp

  result = @[]
  for fp in bestById.values:
    result.add(fp)


proc detectAllOs*(banner: string, probe: ServiceProbe): seq[OsFingerprint] =

  dedupeOs(
    fingerprintAllOs(
      banner,
      probe
    )
  )