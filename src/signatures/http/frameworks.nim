## =============================================================================
## signatures/http/frameworks.nim
##
## Signatures pour les frameworks web. headersOnly varie selon la source du
## signal : les en-têtes (Server:, X-Powered-By:) sont headersOnly: true,
## les cookies/contenus qui peuvent apparaître ailleurs dans la réponse
## restent headersOnly: false par prudence.
## =============================================================================

import regex

import ../../fingerprint/types

proc getFrameworkSignatures*(): seq[MatchRule] =

  result = @[]

  result.add MatchRule(
    pattern: re2"(?i)X-Powered-By:\s*Express",
    service: sidExpress,
    versionGroup: 0,
    confidence: 95,
    headersOnly: true
  )

  result.add MatchRule(
    pattern: re2"(?i)Server:\s*Werkzeug/?([\d.]*)",
    service: sidFlask,
    versionGroup: 1,
    confidence: 90,
    headersOnly: true
  )

  result.add MatchRule(
    pattern: re2"(?i)laravel_session",
    service: sidLaravel,
    versionGroup: 0,
    confidence: 90,
    headersOnly: false
  )

  result.add MatchRule(
    pattern: re2"(?i)csrftoken",
    service: sidDjango,
    versionGroup: 0,
    confidence: 90,
    headersOnly: false
  )
