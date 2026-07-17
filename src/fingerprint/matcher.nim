##==============================================================
##
### src/fingerprint/matcher.nim
##
##==============================================================

# J'ai modifié l'utilisation de regex match par regex find, pour éviter les exceptions de type AssertionDefect ou RangeDefect.

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
  if headersOnly:
    headers
  else:
    fullBanner

proc extractGroup(
    target: string,
    m: RegexMatch2,
    groupIndex: int
): string =
  if groupIndex < 0:
    return ""

  try:
    let bounds = m.group(groupIndex)
    if bounds != reNonCapture:
      return target[bounds]
  except IndexDefect, RangeDefect:
    discard
  ""

# -----------------------------------------------------------------------------
# Service fingerprinting
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
    let rawTarget = targetFor(rule.headersOnly, headers, banner)
    let target = toSafeString(rawTarget)
    var m: RegexMatch2

    try:
      # Remplacement de match par find
      if target.find(rule.pattern, m):
        return some(buildFingerprint(banner, target, m, rule))
    except AssertionDefect, CatchableError:
      continue

  return none(Fingerprint)


proc fingerprintAll*(
    banner: string,
    probe: ServiceProbe
): seq[Fingerprint] =
  let (headers, _) = splitHttpHeaders(banner)

  for rule in probe.matches:
    let rawTarget = targetFor(rule.headersOnly, headers, banner)
    let target = toSafeString(rawTarget)
    var m: RegexMatch2

    try:
      # Remplacement de match par find
      if target.find(rule.pattern, m):
        result.add(buildFingerprint(banner, target, m, rule))
    except AssertionDefect, CatchableError:
      continue


# -----------------------------------------------------------------------------
# OS fingerprinting
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
    let rawTarget = targetFor(rule.headersOnly, headers, banner)
    let target = toSafeString(rawTarget)
    var m: RegexMatch2

    try:
      # Remplacement de match par find
      if target.find(rule.pattern, m):
        return some(buildOsFingerprint(banner, target, m, rule))
    except AssertionDefect, CatchableError:
      continue

  return none(OsFingerprint)


proc fingerprintAllOs*(
    banner: string,
    probe: ServiceProbe
): seq[OsFingerprint] =
  let (headers, _) = splitHttpHeaders(banner)

  for rule in probe.osMatches:
    let rawTarget = targetFor(rule.headersOnly, headers, banner)
    let target = toSafeString(rawTarget)
    var m: RegexMatch2

    try:
      # Remplacement de match par find
      if target.find(rule.pattern, m):
        result.add(buildOsFingerprint(banner, target, m, rule))
    except AssertionDefect, CatchableError:
      continue