## =============================================================================
## signatures/smb/servers.nim
##
## Signatures des principaux serveurs SMB.
## =============================================================================

import regex
import ../../fingerprint/types


proc getSmbServerSignatures*(): seq[MatchRule] =

  result = @[]

  result.add MatchRule(
    pattern: re2"(?i)Samba[/ ]?(\d[\d.]*)",
    service: sidSamba,
    versionGroup: 0,
    confidence: 100
  )

  result.add MatchRule(
    pattern: re2"(?i)Windows",
    service: sidWindowsSMB,
    versionGroup: -1,
    confidence: 95
  )

  result.add MatchRule(
    pattern: re2"(?i)Microsoft SMB",
    service: sidWindowsSMB,
    versionGroup: -1,
    confidence: 100
  )

  result.add MatchRule(
    pattern: re2"(?i)SMB ?3\.1\.1",
    service: sidSMB311,
    versionGroup: -1,
    confidence: 100
  )

  result.add MatchRule(
    pattern: re2"(?i)SMB ?3\.0",
    service: sidSMB30,
    versionGroup: -1,
    confidence: 95
  )

  result.add MatchRule(
    pattern: re2"(?i)SMB ?2\.1",
    service: sidSMB21,
    versionGroup: -1,
    confidence: 95
  )

  result.add MatchRule(
    pattern: re2"(?i)SMB ?2\.0",
    service: sidSMB20,
    versionGroup: -1,
    confidence: 95
  )

  result.add MatchRule(
    pattern: re2"(?i)Synology",
    service: sidSynologyDSM,
    versionGroup: -1,
    confidence: 90
  )

  result.add MatchRule(
    pattern: re2"(?i)TrueNAS",
    service: sidTrueNAS,
    versionGroup: -1,
    confidence: 90
  )

  result.add MatchRule(
    pattern: re2"(?i)NetApp",
    service: sidNetApp,
    versionGroup: -1,
    confidence: 90
  )

  result.add MatchRule(
    pattern: re2"(?i)QNAP",
    service: sidQNAP,
    versionGroup: -1,
    confidence: 90
  )