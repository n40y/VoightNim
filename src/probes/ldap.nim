## =============================================================================
## src/probes/ldap.nim
##
## Sonde réseau pour le protocole LDAP (Port 389).
## Envoie un ASN.1 Anonymous Bind Request pour provoquer une BindResponse.
## =============================================================================

import ../fingerprint/types
import ../fingerprint/utils
import ../signatures/ldap/init as ldapSignatures


proc getLdapProbe*(): ServiceProbe =
    result = ServiceProbe(
        probeType: ptLDAP,
        name: "LDAP",
        payload: toBytes("\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00"),
        ports: @[389'u16],
        timeoutMs: 1500,
        rarity: 1,
        transport: trTCP,
        matches: ldapSignatures.getLdapSignatures()
    )
