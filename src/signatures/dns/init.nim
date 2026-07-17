## =============================================================================
## signatures/dns/init.nim
##
## Point d'entrée unique pour les signatures DNS.
## =============================================================================

import ../../fingerprint/types
import ./servers


proc getDnsSignatures*(): seq[MatchRule] = 
    result = @[]

    result.add getDnsServerSignatures()
