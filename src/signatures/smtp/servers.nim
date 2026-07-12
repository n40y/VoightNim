## =============================================================================
## signatures/smtp/servers.nim
##
## Signatures pour les serveurs de messagerie (bannière SMTP / réponse EHLO).
## =============================================================================

import regex

import ../../fingerprint/types

proc getSmtpServerSignatures*(): seq[MatchRule] =

  result = @[]

  result.add MatchRule(
    pattern: re2"Postfix",
    service: sidPostfix,
    versionGroup: -1,
    confidence: 100
  )

  result.add MatchRule(
    pattern: re2"Exim (\d[\d.]*)",
    service: sidExim,
    versionGroup: 0,
    confidence: 100
  )

  result.add MatchRule(
    pattern: re2"Microsoft ESMTP",
    service: sidExchange,
    versionGroup: -1,
    confidence: 95
  )

  result.add MatchRule(
    pattern: re2"Sendmail",
    service: sidSendmail,
    versionGroup: -1,
    confidence: 90
  )