## =============================================================================
## src/probes/kerberos.nim
##
## Sonde réseau pour Kerberos v5 via TCP (Port 88).
## Envoie une structure ASN.1 minimale pour déclencher un paquet KRB-ERROR.
## =============================================================================

import ../fingerprint/types
import ../fingerprint/utils
import ../signatures/kerberos/init as kerberosSignatures
import ../fingerprint/proberegistry


proc getKerberosProbe*(): ServiceProbe =
    result = ServiceProbe(
        probeType: ptKerberos,
        name: "Kerberos",
        payload: toBytes("\x00\x00\x00\x0e\x30\x0c\xa0\x03\x02\x01\x05\xa1\x05\x30\x03\x02\x01\x0a"),
        ports: @[88'u16],
        timeoutMs: 1500,
        rarity: 1,
        transport: trTCP,
        matches: kerberosSignatures.getKerberosSignatures()
    )

# Auto-enregistrement : s'ajoute au registre global dès que ce module est
# importé (voir src/fingerprint/registry.nim). Rien d'autre n'a besoin de
# connaître explicitement cette sonde.
registerProbe(getKerberosProbe())