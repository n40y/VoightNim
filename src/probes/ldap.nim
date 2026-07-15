## =============================================================================
## src/probes/ldap.nim
##
## Sonde réseau pour le protocole LDAP (Port 389).
##
## Envoie une requête LDAP SearchRequest anonyme contre le RootDSE
## (baseObject="", scope=base, filter=(objectClass=*)) plutôt qu'un simple
## BindRequest : un BindResponse ne contient quasiment jamais le nom du
## produit en texte, alors que le RootDSE expose des attributs bien plus
## révélateurs (ex: supportedCapabilities avec les OID Microsoft
## 1.2.840.113556.* pour Active Directory, structuralObjectClass
## "OpenLDAProotDSE" pour OpenLDAP).
## =============================================================================

import ../fingerprint/types
import ../fingerprint/utils
import ../signatures/ldap/init as ldapSignatures


proc getLdapProbe*(): ServiceProbe =
    result = ServiceProbe(
        probeType: ptLDAP,
        name: "LDAP",
        payload: toBytes(
            "\x30\x25\x02\x01\x01\x63\x20\x04\x00\x0a\x01\x00\x0a\x01\x00" &
            "\x02\x01\x00\x02\x01\x00\x01\x01\x00\x87\x0b\x6f\x62\x6a\x65" &
            "\x63\x74\x43\x6c\x61\x73\x73\x30\x00"
        ),
        ports: @[389'u16],
        timeoutMs: 1500,
        rarity: 1,
        transport: trTCP,
        matches: ldapSignatures.getLdapSignatures()
    )