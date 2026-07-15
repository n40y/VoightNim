## =============================================================================
## signatures/ldap/init.nim
##
## Point d'entrée unique pour les signatures LDAP.
## =============================================================================


import ../../fingerprint/types
import ./servers


proc getLdapSignatures*(): seq[MatchRule] = 
    result = @[]

    result.add getLdapServerSignatures()
