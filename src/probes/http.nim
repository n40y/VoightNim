## ================================================= 
## src/probes/http.nim
##
## Sonde de connexion pour le protocole HTTP / HTTPS.
##
## 443 et 8443 sont conventionnellement du HTTPS : le serveur y attend un
## handshake TLS avant tout octet HTTP. Envoyer la requête GET en clair sur
## ces ports (comme c'était le cas auparavant, transport: trTCP partout)
## n'obtient jamais de réponse. On garde donc le même payload/mêmes
## signatures, mais avec deux sondes séparées par transport.
## =================================================

import ../fingerprint/types
import ../fingerprint/utils
import ../signatures/http/init as httpSignatures
import ../signatures/os/init as osSignatures
import ../fingerprint/proberegistry

const httpGetPayload = toBytes(
  "GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: VoightNim/1.0\r\nConnection: close\r\n\r\n"
)
# NB: le "Host: localhost" ci-dessus est remplacé dynamiquement par l'IP
# cible réelle dans executeProbe (voir prober.nim, réécriture pour ptHTTP).

proc getHttpProbe*(): ServiceProbe =
  result = ServiceProbe(
    probeType: ptHTTP,
    name: "HTTP",
    payload: httpGetPayload,
    ports: @[80'u16, 8000'u16, 8080'u16, 8888'u16],
    timeoutMs: 1500,
    rarity: 1,
    transport: trTCP,
    matches: httpSignatures.getHttpSignatures(),
    osMatches: osSignatures.getOsSignatures()
  )

proc getHttpsProbe*(): ServiceProbe =
  result = ServiceProbe(
    probeType: ptHTTP,
    name: "HTTPS",
    payload: httpGetPayload,
    ports: @[443'u16, 8443'u16],
    timeoutMs: 1500,
    rarity: 1,
    transport: trTLS,
    matches: httpSignatures.getHttpSignatures(),
    osMatches: osSignatures.getOsSignatures()
  )

# Auto-enregistrement : s'ajoute au registre global dès que ce module est
# importé (voir src/fingerprint/registry.nim). Rien d'autre n'a besoin de
# connaître explicitement cette sonde.
registerProbe(getHttpProbe())
registerProbe(getHttpsProbe())