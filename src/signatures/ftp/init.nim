## =============================================================================
## signatures/ftp/init.nim
##
## Point d'entrée unique pour les signatures FTP.
## =============================================================================

import ../../fingerprint/types
import ./servers

proc getFtpSignatures*(): seq[MatchRule] =
  result = @[]

  result.add getFtpServerSignatures()