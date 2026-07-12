## =============================================================================
## signatures/smtp/servers.nim
##
## Signatures pour les serveurs de messagerie (bannière SMTP / réponse EHLO).
## =============================================================================

import re2

import ../../types

proc getSmtpServerSignatures*(): seq[MatchRule] =

  result = @[]

  result.add MatchRule(
    pattern: re2"Postfix",
    service: sidPostfix,
    versionGroup: 0,
    confidence: 100
  )

  result.add MatchRule(
    pattern: re2"Exim (\d[\d.]*)",
    service: sidExim,
    versionGroup: 1,
    confidence: 100
  )

  result.add MatchRule(
    pattern: re2"Microsoft ESMTP",
    service: sidExchange,
    versionGroup: 0,
    confidence: 95
  )

  result.add MatchRule(
    pattern: re2"Sendmail",
    service: sidSendmail,
    versionGroup: 0,
    confidence: 90
  )
