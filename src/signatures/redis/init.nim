## =============================================================================
## signatures/redis/init.nim
##
## Point d'entrée unique pour les signatures Redis.
## =============================================================================

import ../../fingerprint/types
import ./servers

proc getRedisSignatures*(): seq[MatchRule] =
  result = @[]

  result.add getRedisServerSignatures()