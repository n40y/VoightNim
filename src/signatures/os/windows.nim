## =============================================================================
## signatures/os/windows.nim
##
## Signatures OS pour Windows. IIS implique Windows avec une confiance
## élevée même sans mention explicite dans le banner (produit propriétaire
## Microsoft, jamais porté sur un autre OS).
## =============================================================================

import regex

import ../../fingerprint/types

proc getWindowsOsSignatures*(): seq[OsMatchRule] =

  result = @[]

  result.add OsMatchRule(
    pattern: re2"(?i)Server:\s*Microsoft-IIS",
    os: osWindows,
    versionGroup: -1,
    confidence: 90,
    headersOnly: true
  )

  result.add OsMatchRule(
    pattern: re2"(?i)Server:.*\(Win(32|64)\)",
    os: osWindows,
    versionGroup: -1,
    confidence: 90,
    headersOnly: true
  )

  result.add OsMatchRule(
    pattern: re2"(?i)X-Powered-By:\s*ASP\.NET",
    os: osWindows,
    versionGroup: -1,
    confidence: 70,
    headersOnly: true
  )