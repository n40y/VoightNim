# src/probes/http.nim

import ../fingerprint/types
import ../fingerprint/utils
import ../signatures/http/init as httpSignatures
import ../signatures/os/init as osSignatures

proc getHttpProbe*(): ServiceProbe =
  result = ServiceProbe(
    probeType: ptHTTP,

    name: "HTTP",

    payload: toBytes(
      "GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: VoightNim/1.0\r\nConnection: close\r\n\r\n"
    ),

    ports: @[80'u16, 8080'u16, 8000'u16, 8443'u16],

    timeoutMs: 1500,

    rarity: 1,

    ssl: false,

    matches: httpSignatures.getHttpSignatures(),

    osMatches: osSignatures.getOsSignatures()
  )
