## =============================================================================
## src/probes/ldap.nim
##
## Sonde réseau pour le protocole LDAP (Ports: 389, 636, 3268, 3269).
##
## Envoie une requête LDAP SearchRequest anonyme contre le RootDSE
## (baseObject="", scope=base, filter=(objectClass=*)) plutôt qu'un simple
## BindRequest : un BindResponse ne contient quasiment jamais le nom du
## produit en texte, alors que le RootDSE expose des attributs bien plus
## révélateurs (ex: supportedCapabilities avec les OID Microsoft
## 1.2.840.113556.* pour Active Directory, structuralObjectClass
## "OpenLDAProotDSE" pour OpenLDAP).
##
## Port 389 (LDAP) et 3268 (Global Catalog) parlent BER en clair sur TCP.
## Port 636 (LDAPS) et 3269 (GC over TLS) attendent un handshake TLS avant
## tout échange LDAP : envoyer le même BER en clair dessus ne reçoit jamais
## de réponse (le serveur attend un ClientHello, pas un SearchRequest). Deux
## sondes distinctes sont donc nécessaires, avec le même payload/matches
## mais un transport différent.
## =============================================================================

import ../fingerprint/types
import ../fingerprint/utils
import ../signatures/ldap/init as ldapSignatures
import ../fingerprint/proberegistry

const ldapSearchRootDsePayload = toBytes(
    "\x30\x25\x02\x01\x01\x63\x20\x04\x00\x0a\x01\x00\x0a\x01\x00" &
    "\x02\x01\x00\x02\x01\x00\x01\x01\x00\x87\x0b\x6f\x62\x6a\x65" &
    "\x63\x74\x43\x6c\x61\x73\x73\x30\x00"
)

proc getLdapProbe*(): ServiceProbe =
    result = ServiceProbe(
        probeType: ptLDAP,
        name: "LDAP",
        payload: ldapSearchRootDsePayload,
        ports: @[389'u16, 3268'u16],
        timeoutMs: 1500,
        rarity: 1,
        transport: trTCP,
        matches: ldapSignatures.getLdapSignatures()
    )

proc getLdapsProbe*(): ServiceProbe =
    result = ServiceProbe(
        probeType: ptLDAP,
        name: "LDAPS",
        payload: ldapSearchRootDsePayload,
        ports: @[636'u16, 3269'u16],
        timeoutMs: 1500,
        rarity: 1,
        transport: trTLS,
        matches: ldapSignatures.getLdapSignatures()
    )

# Auto-enregistrement : s'ajoute au registre global dès que ce module est
# importé (voir src/fingerprint/registry.nim). Rien d'autre n'a besoin de
# connaître explicitement cette sonde.
registerProbe(getLdapProbe())
registerProbe(getLdapsProbe())