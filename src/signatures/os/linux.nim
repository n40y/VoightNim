## =============================================================================
## signatures/os/linux.nim
##
## Signatures OS pour les distributions Linux, détectées via les
## indices que certains logiciels ajoutent à leur propre bannière
## (ex: Apache "(Ubuntu)", suffixe de paquet OpenSSH "Ubuntu-...").
## =============================================================================

import regex

import ../../fingerprint/types

proc getLinuxOsSignatures*(): seq[OsMatchRule] =

  result = @[]

  # ---------------------------------------------------------------------------
  # Via en-tête HTTP "Server:" (ex: Apache/2.4.41 (Ubuntu))
  # ---------------------------------------------------------------------------

  result.add OsMatchRule(
    pattern: re2"(?i)Server:.*\(Ubuntu\)",
    os: osUbuntu,
    versionGroup: 0,
    confidence: 85,
    headersOnly: true
  )

  result.add OsMatchRule(
    pattern: re2"(?i)Server:.*\(Debian\)",
    os: osDebian,
    versionGroup: 0,
    confidence: 85,
    headersOnly: true
  )

  result.add OsMatchRule(
    pattern: re2"(?i)Server:.*\(CentOS\)",
    os: osCentOS,
    versionGroup: 0,
    confidence: 85,
    headersOnly: true
  )

  result.add OsMatchRule(
    pattern: re2"(?i)Server:.*\(Red Hat\)",
    os: osRHEL,
    versionGroup: 0,
    confidence: 85,
    headersOnly: true
  )

  result.add OsMatchRule(
    pattern: re2"(?i)Server:.*\(Fedora\)",
    os: osFedora,
    versionGroup: 0,
    confidence: 85,
    headersOnly: true
  )

  # ---------------------------------------------------------------------------
  # Via bannière SSH (suffixe de paquet distro sur le nom de version OpenSSH)
  # ---------------------------------------------------------------------------

  result.add OsMatchRule(
    pattern: re2"OpenSSH_[\d.]+p?\d*\s+Ubuntu",
    os: osUbuntu,
    versionGroup: 0,
    confidence: 80,
    headersOnly: false
  )

  result.add OsMatchRule(
    pattern: re2"OpenSSH_[\d.]+p?\d*\s+Debian",
    os: osDebian,
    versionGroup: 0,
    confidence: 80,
    headersOnly: false
  )
