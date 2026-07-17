# src/fingerprint/engine.nim

import std/options

import types
import matcher

# -----------------------------------------------------------------------------
# Axe "service"
# -----------------------------------------------------------------------------

proc detect*(
    banner: string,
    probe: ServiceProbe
): Option[Fingerprint] =

  fingerprint(
    banner,
    probe
  )


proc detectAll*(
    banner: string,
    probe: ServiceProbe
): seq[Fingerprint] =

  fingerprintAll(
    banner,
    probe
  )


proc detectBest*(
    banner: string,
    probes: seq[ServiceProbe]
): Option[Fingerprint] =

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

proc detectOs*(
    banner: string,
    probe: ServiceProbe
): Option[OsFingerprint] =

  fingerprintOs(
    banner,
    probe
  )


proc detectAllOs*(
    banner: string,
    probe: ServiceProbe
): seq[OsFingerprint] =

  fingerprintAllOs(
    banner,
    probe
  )