## =============================================================================
## signatures/kerberos/init.nim
##
## Point d'entrée unique pour les signatures Kerberos.
## =============================================================================

import ../../fingerprint/types

import ./servers


proc getKerberosSignatures*(): seq[MatchRule] =
    result = @[]

    result.add getKerberosServerSignatures()
