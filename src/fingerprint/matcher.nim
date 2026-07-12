# src/fingerprint/matcher.nim

import std/options
import regex

import types
import services
import osCatalog
import utils

proc targetFor(
    headersOnly: bool,
    headers: string,
    fullBanner: string
): string =
  ## Choisit sur quelle partie du banner appliquer la regex de la règle.
  if headersOnly:
    headers
  else:
    fullBanner

proc extractGroup(
    target: string,
    m: RegexMatch2,
    groupIndex: int
): string =
  ## groupIndex est 0-indexé PARMI LES GROUPES CAPTURANTS (pas le match
  ## entier) : re2"Server: nginx/([\d.]+)" n'a qu'un seul groupe, donc sa
  ## version est à l'index 0. -1 signifie "pas de version à extraire".
  if groupIndex < 0:
    return ""

  try:
    let bounds = m.group(groupIndex)

    # reNonCapture : le groupe existe dans le pattern mais n'a pas participé
    # à ce match précis (ex: groupe optionnel absent)
    if bounds != reNonCapture:
      return target[bounds]

  except IndexDefect, RangeDefect:
    discard  # ce numéro de groupe n'existe pas du tout dans ce pattern

  ""

# -----------------------------------------------------------------------------
# Axe "service" (technologie détectée : nginx, PHP, Redis...)
# -----------------------------------------------------------------------------

proc buildFingerprint(
    fullBanner: string,
    target: string,
    m: RegexMatch2,
    rule: MatchRule
): Fingerprint =

  result.info = getService(rule.service)
  result.version = extractGroup(target, m, rule.versionGroup)
  result.confidence = rule.confidence
  result.banner = fullBanner


proc fingerprint*(
    banner: string,
    probe: ServiceProbe
): Option[Fingerprint] =

  let (headers, _) = splitHttpHeaders(banner)

  for rule in probe.matches:

    let target = targetFor(rule.headersOnly, headers, banner)
    var m: RegexMatch2

    if target.match(rule.pattern, m):

      return some(buildFingerprint(
        banner,
        target,
        m,
        rule
      ))

  return none(Fingerprint)


proc fingerprintAll*(
    banner: string,
    probe: ServiceProbe
): seq[Fingerprint] =

  let (headers, _) = splitHttpHeaders(banner)

  for rule in probe.matches:

    let target = targetFor(rule.headersOnly, headers, banner)
    var m: RegexMatch2

    if target.match(rule.pattern, m):

      result.add(
        buildFingerprint(
          banner,
          target,
          m,
          rule
        )
      )

# -----------------------------------------------------------------------------
# Axe "OS" (système d'exploitation détecté : Ubuntu, Windows...)
# -----------------------------------------------------------------------------

proc buildOsFingerprint(
    fullBanner: string,
    target: string,
    m: RegexMatch2,
    rule: OsMatchRule
): OsFingerprint =

  result.info = getOs(rule.os)
  result.version = extractGroup(target, m, rule.versionGroup)
  result.confidence = rule.confidence
  result.banner = fullBanner


proc fingerprintOs*(
    banner: string,
    probe: ServiceProbe
): Option[OsFingerprint] =

  let (headers, _) = splitHttpHeaders(banner)

  for rule in probe.osMatches:

    let target = targetFor(rule.headersOnly, headers, banner)
    var m: RegexMatch2

    if target.match(rule.pattern, m):

      return some(buildOsFingerprint(
        banner,
        target,
        m,
        rule
      ))

  return none(OsFingerprint)


proc fingerprintAllOs*(
    banner: string,
    probe: ServiceProbe
): seq[OsFingerprint] =

  let (headers, _) = splitHttpHeaders(banner)

  for rule in probe.osMatches:

    let target = targetFor(rule.headersOnly, headers, banner)
    var m: RegexMatch2

    if target.match(rule.pattern, m):

      result.add(
        buildOsFingerprint(
          banner,
          target,
          m,
          rule
        )
      )