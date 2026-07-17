## ================================================= 
## src/probes/dns.nim
##
## Sonde de connexion pour le DNS.
## 
## =================================================


import ../fingerprint/types
import ../fingerprint/utils
import ../fingerprint/proberegistry
import ../signatures/dns/init


proc getDnsProbe*(): ServiceProbe =
    # Construction d'une requête DNS standard sur TCP :
    # [2 octets] Longueur du message TCP (\x00\x11 = 17 octets restants)
    # [2 octets] Transaction ID (\x42\x42) -> Requis pour ta première signature
    # [2 octets] Flags (\x01\x00 = Standard Query avec récursivité)
    # [6 octets] Questions (\x00\x01), Answer RRs (\x00\x00), Authority RRs (\x00\x00), Additional RRs (\x00\x00)
    # [5 octets] Query payload (\x00 = Root ".", \x00\x01 = Type A, \x00\x01 = Class IN)
    let dnsPayload = toBytes("\x00\x11\x42\x42\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01")

    result = ServiceProbe(
        probeType: ptDNS,
        name: "DNS",
        payload: dnsPayload,
        ports: @[53'u16],
        timeoutMs: 1500,
        rarity: 1,
        transport: trTCP,
        matches: getDnsSignatures(),
        enabled: true
    )

registerProbe(getDnsProbe())