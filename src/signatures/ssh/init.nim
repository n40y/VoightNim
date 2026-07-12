## =============================================================================
## signatures/ssh/init.nim
##
## Point d'entrée unique pour les signatures SSH.
## =============================================================================

import ../../types
import ./servers

proc getSshSignatures*(): seq[MatchRule] =
  result = @[]

  result.add getSshServerSignatures()
