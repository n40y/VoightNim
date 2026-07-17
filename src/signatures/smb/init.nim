## =============================================================================
## signatures/smb/init.nim
##
## Point d'entrée unique pour les signatures SMB.
## =============================================================================

import ../../fingerprint/types
import ./servers


proc getSmbSignatures*(): seq[MatchRule] =
    result = @[]

    result.add getSmbServerSignatures()