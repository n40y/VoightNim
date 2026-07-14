## =============================================================================
## signatures/ldap/servers.nim
##
## Signatures des principaux serveurs LDAP.
## =============================================================================

import regex

import ../../fingerprint/types


proc getLdapServerSignatures*(): seq[MatchRule] =

  result = @[]

  # ---------------------------------------------------------------------------
  # Microsoft Active Directory
  #
  # Le RootDSE d'un AD expose supportedCapabilities avec des OID préfixés
  # 1.2.840.113556 (branche IANA privée de Microsoft) — beaucoup plus fiable
  # que de chercher "Active Directory" en toutes lettres, qui n'apparaît
  # jamais dans une réponse LDAP brute.
  # ---------------------------------------------------------------------------

  result.add MatchRule(
    pattern: re2"1\.2\.840\.113556",
    service: sidActiveDirectory,
    versionGroup: -1,
    confidence: 100
  )

  # ---------------------------------------------------------------------------
  # OpenLDAP
  #
  # Le RootDSE contient généralement structuralObjectClass: OpenLDAProotDSE
  # en toutes lettres.
  # ---------------------------------------------------------------------------

  result.add MatchRule(
    pattern: re2"(?i)OpenLDAProotDSE",
    service: sidOpenLDAP,
    versionGroup: -1,
    confidence: 100
  )

  result.add MatchRule(
    pattern: re2"(?i)OpenLDAP[/ ]?(\d[\d.]*)",
    service: sidOpenLDAP,
    versionGroup: 0,
    confidence: 90
  )

  # ---------------------------------------------------------------------------
  # Apache Directory Server
  # ---------------------------------------------------------------------------

  result.add MatchRule(
    pattern: re2"(?i)ApacheDS[/ ]?(\d[\d.]*)",
    service: sidApacheDS,
    versionGroup: 0,
    confidence: 90
  )

  # ---------------------------------------------------------------------------
  # 389 Directory Server
  # ---------------------------------------------------------------------------

  result.add MatchRule(
    pattern: re2"(?i)389 Directory Server[/ ]?(\d[\d.]*)",
    service: sid389DirectoryServer,
    versionGroup: 0,
    confidence: 90
  )

  # ---------------------------------------------------------------------------
  # Red Hat Directory Server
  # ---------------------------------------------------------------------------

  result.add MatchRule(
    pattern: re2"(?i)Red Hat Directory Server",
    service: sidRedHatDirectoryServer,
    versionGroup: -1,
    confidence: 90
  )

  # ---------------------------------------------------------------------------
  # OpenDJ / OpenDS
  # ---------------------------------------------------------------------------

  result.add MatchRule(
    pattern: re2"(?i)OpenDJ[/ ]?(\d[\d.]*)",
    service: sidOpenDJ,
    versionGroup: 0,
    confidence: 90
  )

  result.add MatchRule(
    pattern: re2"(?i)OpenDS[/ ]?(\d[\d.]*)",
    service: sidOpenDS,
    versionGroup: 0,
    confidence: 90
  )

  # ---------------------------------------------------------------------------
  # Oracle Unified Directory / IBM / ForgeRock
  # ---------------------------------------------------------------------------

  result.add MatchRule(
    pattern: re2"(?i)Oracle Unified Directory",
    service: sidOracleUnifiedDirectory,
    versionGroup: -1,
    confidence: 90
  )

  result.add MatchRule(
    pattern: re2"(?i)IBM Security Directory Server",
    service: sidIBMSecurityDirectoryServer,
    versionGroup: -1,
    confidence: 90
  )

  result.add MatchRule(
    pattern: re2"(?i)ForgeRock Directory Services",
    service: sidForgeRockDS,
    versionGroup: -1,
    confidence: 90
  )
