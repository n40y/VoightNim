## =============================================================================
## signatures/msrpc/init.nim
##
## Point d'entrée unique pour les signatures MSRPC.
## =============================================================================

import ../../fingerprint/types
import ./servers


proc getRpcEpmapSignatures*(): seq[MatchRule] =
    result = @[]

    result.add getRpcEpmapServerSignatures()