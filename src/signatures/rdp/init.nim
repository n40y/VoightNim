## =============================================================================
## signatures/rdp/init.nim
##
## Point d'entrée unique pour les signatures RDP.
## =============================================================================

import ../../fingerprint/types
import ./servers


proc getRdpSignatures*(): seq[MatchRule] =
    result = @[]
    result.add getRdpClassicSignatures()