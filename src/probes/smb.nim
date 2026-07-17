## =============================================================================
## src/probes/smb.nim
##
## Sonde réseau pour le protocole SMB (Port 445).
## Envoie une requête SMB Négociate standard.
## =============================================================================

import ../fingerprint/types
import ../fingerprint/utils
import ../fingerprint/proberegistry

proc getSmbV1Probe*(): ServiceProbe =
    result = ServiceProbe(
        probeType: ptSMB,
        name:      "SMBv1-Negotiate",
        # Chaîne binaire complète sans coupure
        payload:   toBytes("\x00\x00\x00\x2f\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x3a\x15\x00\x00\xff\xfe\x00\x00\x00\x00\x00\x0c\x00\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00"),
        ports:     @[445'u16],
        transport: trTCP   
    )

proc getSmbV2Probe*(): ServiceProbe =
    result = ServiceProbe(
        probeType: ptSMB,
        name:      "SMBv2-Negotiate",
        # Chaîne binaire complète sans coupure
        payload:   toBytes("\x00\x00\x00\x44\xfe\x53\x4d\x42\x40\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x24\x00\x01\x00\x01\x02\x00\x00"),
        ports:     @[445'u16],
        transport: trTCP
    )

# Enregistrement automatique dans le moteur
registerProbe(getSmbV1Probe())
registerProbe(getSmbV2Probe())