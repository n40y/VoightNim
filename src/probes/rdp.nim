## ================================================
## src/probes/rdp.nim
## 
## Sonde réseau pour le protocole RDP (Port 3389).
## Envoie un payload de connexion X.224
## ================================================

import ../fingerprint/types
import ../fingerprint/utils
import ../fingerprint/proberegistry

import ../signatures/rdp/init

proc getRdpProbe*(): ServiceProbe =
    result = ServiceProbe(
        probeType: ptRDP,
        name:       "RDP",
        payload:    toBytes("\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00"),
        ports:      @[3389'u16],
        timeoutMs:  1500,
        rarity:     1,
        transport:  trTCP,
        matches:    getRdpSignatures() # Charge dynamiquement les signatures RDP.
    )

registerProbe(getRdpProbe())