## =============================================================================
## src/probes/msrpc.nim
## 
## Sonde réseau pour le protocole Microsoft RPC Endpoint Mapper (Port 135).
## Envoie un paquet DCERPC Bind Request binaire pour forcer une réponse.
## =============================================================================

import ../fingerprint/types
import ../fingerprint/utils
import ../fingerprint/proberegistry
import ../signatures/msrpc/init


proc getMsrpcProbe(): ServiceProbe =
    # Payload binaire : DCERPC Bind Request vers l'UUID de l'Endpoint Mapper (EPMAP)
    # Version : 5.0 (\x05\x00) | Packet Type : Bind (\x0b)
    let msrpcPayload = toBytes(
        "\x05\x00\x0b\x03\x10\x00\x00\x00\x48\x00\x00\x00\x01\x00\x00\x00" &
        "\xd0\x16\xd0\x16\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x01\x00" &
        "\xac\x5d\xaf\xe1\x57\xee\xd0\x11\xa1\x94\x00\xa0\xc9\x1b\xad\x63" & 
        "\x01\x00\x00\x00\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00" &
        "\x2b\x10\x48\x60\x02\x00\x00\x00"
    )

    result = ServiceProbe(
        probeType: ptRPC,
        name: "MSRPC",
        payload: msrpcPayload,
        ports: @[135'u16],
        timeoutMs: 1500,
        rarity: 1,
        transport: trTCP,
        matches: getRpcEpmapSignatures(),
        enabled: true
    )

registerProbe(getMsrpcProbe())