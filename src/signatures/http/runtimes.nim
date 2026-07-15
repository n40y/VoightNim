## =============================================================================
## signatures/http/runtimes.nim
##
## Signatures pour les langages et runtimes détectés via l'en-tête
## X-Powered-By (ou équivalent). Toujours headersOnly: true, cette
## information ne provient jamais du corps de la réponse.
## =============================================================================

import regex

import ../../fingerprint/types

proc getRuntimeSignatures*(): seq[MatchRule] =

  result = @[]

  result.add MatchRule(
    pattern: re2"(?i)X-Powered-By:\s*PHP(?:/([\d.]+))?",
    service: sidPHP,
    versionGroup: 0,
    confidence: 95,
    headersOnly: true
  )

  result.add MatchRule(
    pattern: re2"(?i)X-Powered-By:\s*ASP\.NET",
    service: sidASPNet,
    versionGroup: -1,
    confidence: 95,
    headersOnly: true
  )

  result.add MatchRule(
    pattern: re2"(?i)X-AspNet-Version:\s*([\d.]+)",
    service: sidASPNet,
    versionGroup: 0,
    confidence: 95,
    headersOnly: true
  )
