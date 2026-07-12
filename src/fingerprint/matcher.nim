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

# -----------------------------------------------------------------------------
# Axe "service" (technologie détectée : nginx, PHP, Redis...)
# -----------------------------------------------------------------------------

proc captureVersion(
    target: string,
    rule: MatchRule
): string =

  if rule.versionGroup <= 0:
    return ""

  var groups: seq[string]

  if rule.pattern.match(target, groups):

    if rule.versionGroup < groups.len:
      return groups[rule.versionGroup]

  ""

proc buildFingerprint(
    fullBanner: string,
    target: string,
    rule: MatchRule
): Fingerprint =

  result.info = getService(rule.service)
  result.version = captureVersion(target, rule)
  result.confidence = rule.confidence
  result.banner = fullBanner


proc fingerprint*(
    banner: string,
    probe: ServiceProbe
): Option[Fingerprint] =

  let (headers, _) = splitHttpHeaders(banner)

  for rule in probe.matches:

    let target = targetFor(rule.headersOnly, headers, banner)
    var groups: seq[string]

    if rule.pattern.match(target, groups):

      return some(buildFingerprint(
        banner,
        target,
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
    var groups: seq[string]

    if rule.pattern.match(target, groups):

      result.add(
        buildFingerprint(
          banner,
          target,
          rule
        )
      )

# -----------------------------------------------------------------------------
# Axe "OS" (système d'exploitation détecté : Ubuntu, Windows...)
# -----------------------------------------------------------------------------

proc captureOsVersion(
    target: string,
    rule: OsMatchRule
): string =

  if rule.versionGroup <= 0:
    return ""

  var groups: seq[string]

  if rule.pattern.match(target, groups):

    if rule.versionGroup < groups.len:
      return groups[rule.versionGroup]

  ""

proc buildOsFingerprint(
    fullBanner: string,
    target: string,
    rule: OsMatchRule
): OsFingerprint =

  result.info = getOs(rule.os)
  result.version = captureOsVersion(target, rule)
  result.confidence = rule.confidence
  result.banner = fullBanner


proc fingerprintOs*(
    banner: string,
    probe: ServiceProbe
): Option[OsFingerprint] =

  let (headers, _) = splitHttpHeaders(banner)

  for rule in probe.osMatches:

    let target = targetFor(rule.headersOnly, headers, banner)
    var groups: seq[string]

    if rule.pattern.match(target, groups):

      return some(buildOsFingerprint(
        banner,
        target,
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
    var groups: seq[string]

    if rule.pattern.match(target, groups):

      result.add(
        buildOsFingerprint(
          banner,
          target,
          rule
        )
      )
