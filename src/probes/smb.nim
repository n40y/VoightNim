## =============================================================================
## src/probes/smb.nim
##
## Sonde réseau pour le protocole SMB (Port 445).
## Envoie une requête SMBv2 Négociate standard.
## =============================================================================

import ../fingerprint/types
import ../fingerprint/utils
import ../signatures/smb/init as smbSignatures
import ../fingerprint/proberegistry


proc getSmbProbe*(): ServiceProbe =
    result = ServiceProbe(
        probeType : ptSMB,
        name: "SMB",
        payload: toBytes(
            "\x00\x00\x00\x44\xfe\x53\x4d\x42\x40\x00\x00\x00\x00\x00\x00\x00" &
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00" &
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" &
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        ),
        ports: @[445'u16],
        timeoutMs: 1500,
        rarity: 1,
        transport: trTCP,
        matches: smbSignatures.getSmbSignatures()
    )

# Auto-enregistrement : s'ajoute au registre global dès que ce module est
# importé (voir src/fingerprint/registry.nim). Rien d'autre n'a besoin de
# connaître explicitement cette sonde.
registerProbe(getSmbProbe())