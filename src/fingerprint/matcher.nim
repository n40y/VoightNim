import std/options
import re2

import types

proc captureVersion(
    banner: string,
    rule: MatchRule
): string =

  if rule.versionGroup <= 0:
    return ""

  var groups: seq[string]

  if rule.pattern.match(banner, groups):

    if rule.versionGroup < groups.len:
      return groups[rule.versionGroup]

  ""

proc buildFingerprint(
    banner: string,
    probe: ServiceProbe,
    rule: MatchRule
): Fingerprint =

  result.service = probe.probeType

  result.product = rule.product
  result.vendor = rule.vendor
  result.family = rule.family

  result.os = rule.os
  result.device = rule.device

  result.version = captureVersion(banner, rule)

  result.cpe = rule.cpe

  result.banner = banner

  result.confidence = rule.confidence


proc fingerprint*(
    banner: string,
    probe: ServiceProbe
): Option[Fingerprint] =

  for rule in probe.matches:

    var groups: seq[string]

    if rule.pattern.match(banner, groups):

      return some(buildFingerprint(
        banner,
        probe,
        rule
      ))

  return none(Fingerprint)


proc fingerprintAll*(
    banner: string,
    probe: ServiceProbe
): seq[Fingerprint] =

  for rule in probe.matches:

    var groups: seq[string]

    if rule.pattern.match(banner, groups):

      result.add(
        buildFingerprint(
          banner,
          probe,
          rule
        )
      )
