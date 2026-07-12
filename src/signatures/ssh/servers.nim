## =============================================================================
## signatures/ssh/servers.nim
##
## Signatures pour les implémentations serveur SSH, détectées via la
## chaîne d'identification de version envoyée en clair à la connexion
## (RFC 4253 §4.2 : "SSH-protoversion-softwareversion ...").
## headersOnly n'a pas de sens ici (pas de notion d'en-têtes en SSH),
## on laisse la valeur par défaut (false).
## =============================================================================

import regex

import ../../fingerprint/types

proc getSshServerSignatures*(): seq[MatchRule] =

  result = @[]

  result.add MatchRule(
    pattern: re2"OpenSSH[_-]([\d.p]+)",
    service: sidOpenSSH,
    versionGroup: 0,
    confidence: 100
  )

  result.add MatchRule(
    pattern: re2"libssh-([\d.]+)",
    service: sidLibSSH,
    versionGroup: 0,
    confidence: 100
  )

  result.add MatchRule(
    pattern: re2"Dropbear_([\d.]+)",
    service: sidDropbear,
    versionGroup: 0,
    confidence: 100
  )

  result.add MatchRule(
    pattern: re2"Cisco SSH-([\d.]+)",
    service: sidCiscoSSH,
    versionGroup: 0,
    confidence: 100
  )

  result.add MatchRule(
    pattern: re2"Sun_SSH-([\d.]+)",
    service: sidSunSSH,
    versionGroup: 0,
    confidence: 100
  )