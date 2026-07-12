## =============================================================================
## signatures/smtp/init.nim
##
## Point d'entrée unique pour les signatures SMTP.
## =============================================================================

import ../../types
import ./servers

proc getSmtpSignatures*(): seq[MatchRule] =
  result = @[]

  result.add getSmtpServerSignatures()
