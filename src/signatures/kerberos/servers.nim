## =============================================================================
## signatures/kerberos/servers.nim
##
## Signatures des principales implémentations Kerberos.
## =============================================================================

import regex

import ../../fingerprint/types

proc getKerberosServerSignatures*(): seq[MatchRule] =

  result = @[]

  result.add MatchRule(
    pattern: re2"(?i)MIT Kerberos",
    service: sidMITKerberos,
    versionGroup: -1,
    confidence: 100
  )

  result.add MatchRule(
    pattern: re2"(?i)Heimdal",
    service: sidHeimdal,
    versionGroup: -1,
    confidence: 100
  )

  result.add MatchRule(
    pattern: re2"(?i)Microsoft Kerberos",
    service: sidMicrosoftKerberos,
    versionGroup: -1,
    confidence: 100
  )

  result.add MatchRule(
    pattern: re2"(?i)Active Directory",
    service: sidMicrosoftKerberos,
    versionGroup: -1,
    confidence: 95
  )

  result.add MatchRule(
    pattern: re2"(?i)FreeIPA",
    service: sidFreeIPA,
    versionGroup: -1,
    confidence: 95
  )

  result.add MatchRule(
    pattern: re2"(?i)Samba",
    service: sidSambaKerberos,
    versionGroup: -1,
    confidence: 90
  )

  result.add MatchRule(
    pattern: re2"(?i)krb5",
    service: sidKerberos,
    versionGroup: -1,
    confidence: 85
  )

  result.add MatchRule(
    pattern: re2"(?i)Kerberos",
    service: sidKerberos,
    versionGroup: -1,
    confidence: 80
  )