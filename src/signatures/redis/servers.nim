## =============================================================================
## signatures/redis/servers.nim
##
## Signature pour Redis, détectée via la réponse à la commande INFO.
## =============================================================================

import re2

import ../../types

proc getRedisServerSignatures*(): seq[MatchRule] =

  result = @[]

  result.add MatchRule(
    pattern: re2"redis_version:([\d.]+)",
    service: sidRedis,
    versionGroup: 1,
    confidence: 100
  )
