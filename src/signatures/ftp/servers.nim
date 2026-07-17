## =============================================================================
## signatures/ftp/servers.nim
##
## Signatures pour les implémentations serveur FTP, détectées via la
## bannière envoyée après connexion (code 220) ou après USER anonymous.
## =============================================================================

import regex

import ../../fingerprint/types

proc getFtpServerSignatures*(): seq[MatchRule] =

  result = @[]

  result.add MatchRule(
    pattern: re2"FileZilla Server",
    service: sidFileZilla,
    versionGroup: -1,
    confidence: 100
  )

  result.add MatchRule(
    pattern: re2"vsFTPd (\d[\d.]*)",
    service: sidVsftpd,
    versionGroup: 0,
    confidence: 100
  )

  result.add MatchRule(
    pattern: re2"ProFTPD (\d[\d.]*)",
    service: sidProFTPd,
    versionGroup: 0,
    confidence: 100
  )

  result.add MatchRule(
    pattern: re2"Pure-FTPd",
    service: sidPureFTPd,
    versionGroup: -1,
    confidence: 95
  )

  result.add MatchRule(
    pattern: re2"Microsoft FTP Service",
    service: sidMicrosoftFTP,
    versionGroup: -1,
    confidence: 100
  )