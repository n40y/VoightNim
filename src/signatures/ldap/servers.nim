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
  # OpenLDAP
  # ---------------------------------------------------------------------------

  result.add MatchRule(
    pattern: re2"(?i)OpenLDAP[/ ]?(\d[\d.]*)",
    service: sidOpenLDAP,
    versionGroup: 0,
    confidence: 100
  )

  result.add MatchRule(
    pattern: re2"(?i)OpenLDAP",
    service: sidOpenLDAP,
    versionGroup: -1,
    confidence: 95
  )

  # ---------------------------------------------------------------------------
  # Microsoft Active Directory LDAP
  # ---------------------------------------------------------------------------

  result.add MatchRule(
    pattern: re2"(?i)Microsoft.*LDAP",
    service: sidActiveDirectory,
    versionGroup: -1,
    confidence: 100
  )

  result.add MatchRule(
    pattern: re2"(?i)Active Directory",
    service: sidActiveDirectory,
    versionGroup: -1,
    confidence: 100
  )

  result.add MatchRule(
    pattern: re2"(?i)Windows Server",
    service: sidActiveDirectory,
    versionGroup: -1,
    confidence: 90
  )

  # ---------------------------------------------------------------------------
  # Apache Directory Server
  # ---------------------------------------------------------------------------

  result.add MatchRule(
    pattern: re2"(?i)ApacheDS[/ ]?(\d[\d.]*)",
    service: sidApacheDS,
    versionGroup: 0,
    confidence: 100
  )

  result.add MatchRule(
    pattern: re2"(?i)Apache Directory",
    service: sidApacheDS,
    versionGroup: -1,
    confidence: 95
  )

  # ---------------------------------------------------------------------------
  # 389 Directory Server
  # ---------------------------------------------------------------------------

  result.add MatchRule(
    pattern: re2"(?i)389 Directory Server[/ ]?(\d[\d.]*)",
    service: sid389DirectoryServer,
    versionGroup: 0,
    confidence: 100
  )

  result.add MatchRule(
    pattern: re2"(?i)389 Directory",
    service: sid389DirectoryServer,
    versionGroup: -1,
    confidence: 95
  )

  # ---------------------------------------------------------------------------
  # Red Hat Directory Server
  # ---------------------------------------------------------------------------

  result.add MatchRule(
    pattern: re2"(?i)Red Hat Directory Server",
    service: sidRedHatDirectoryServer,
    versionGroup: -1,
    confidence: 100
  )

  # ---------------------------------------------------------------------------
  # OpenDJ
  # ---------------------------------------------------------------------------

  result.add MatchRule(
    pattern: re2"(?i)OpenDJ[/ ]?(\d[\d.]*)",
    service: sidOpenDJ,
    versionGroup: 0,
    confidence: 100
  )

  result.add MatchRule(
    pattern: re2"(?i)OpenDJ",
    service: sidOpenDJ,
    versionGroup: -1,
    confidence: 95
  )

  # ---------------------------------------------------------------------------
  # OpenDS
  # ---------------------------------------------------------------------------

  result.add MatchRule(
    pattern: re2"(?i)OpenDS[/ ]?(\d[\d.]*)",
    service: sidOpenDS,
    versionGroup: 0,
    confidence: 100
  )

  # ---------------------------------------------------------------------------
  # Oracle Unified Directory
  # ---------------------------------------------------------------------------

  result.add MatchRule(
    pattern: re2"(?i)Oracle Unified Directory",
    service: sidOracleUnifiedDirectory,
    versionGroup: -1,
    confidence: 100
  )

  # ---------------------------------------------------------------------------
  # IBM Security Directory Server
  # ---------------------------------------------------------------------------

  result.add MatchRule(
    pattern: re2"(?i)IBM Security Directory Server",
    service: sidIBMSecurityDirectoryServer,
    versionGroup: -1,
    confidence: 100
  )

  # ---------------------------------------------------------------------------
  # ForgeRock DS
  # ---------------------------------------------------------------------------

  result.add MatchRule(
    pattern: re2"(?i)ForgeRock Directory Services",
    service: sidForgeRockDS,
    versionGroup: -1,
    confidence: 100
  )