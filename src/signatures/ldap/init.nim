## =============================================================================
## signatures/kerberos.nim
##
## Point d'entrée unique pour les signatures LDAP.
## =============================================================================


import ../../fingerprint/types
import ./servers


proc getLdapSignatures*(): seqq[MatchRule] = 
    result = @[]

    result.add getLdapServerSignatures()