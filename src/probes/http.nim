## ================================================= 
## src/probes/http.nim
##
## Sonde de connexion pour le protocole HTTP.
## 
## =================================================

import ../fingerprint/types
import ../fingerprint/utils
import ../signatures/http/init as httpSignatures
import ../signatures/os/init as osSignatures
import ../fingerprint/proberegistry


proc getHttpProbe*(): ServiceProbe =
  result = ServiceProbe(
    probeType: ptHTTP,
    name: "HTTP",
    payload: toBytes(
      "GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: VoightNim/1.0\r\nConnection: close\r\n\r\n"
    ),
    ports: @[80'u16, 443'u16, 8000'u16, 8080'u16, 8443'u16, 8888'u16],
    timeoutMs: 1500,
    rarity: 1,
    transport: trTCP,
    matches: httpSignatures.getHttpSignatures(),
    osMatches: osSignatures.getOsSignatures()
  )

# Auto-enregistrement : s'ajoute au registre global dès que ce module est
# importé (voir src/fingerprint/registry.nim). Rien d'autre n'a besoin de
# connaître explicitement cette sonde.
registerProbe(getHttpProbe())