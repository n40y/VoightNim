## =============================================================================
## signatures/dns/servers.nim
##
## Signatures pour la détection du service DNS (Port 53) sur TCP.
## =============================================================================

import regex

import ../../fingerprint/types


proc getDnsServerSignatures*(): seq[MatchRule] =

    result = @[]

    # 1. Détection par Transaction ID fixe (\x42\x42) et bit de réponse (QR)
    # [2 octets de longueur TCP] [2 octets TXID: \x42\x42] [1 octet Flags: >= \x80 (Réponse)]
    result.add MatchRule(
        pattern: re2"^(?s)..\x42\x42[\x80-\xff]",
        service: sidMicrosoftDNS,
        versionGroup: -1,
        confidence: 100,
        headersOnly: false
    )

    # 2. Détection générique d'une réponse DNS TCP (QR bit activé)
    # Utilisé en fallback si le Transaction ID n'est pas fixe.
    result.add MatchRule(
        pattern: re2"^(?s).{4}[\x80-\xff]",
        service: sidMicrosoftDNS,
        versionGroup: -1,
        confidence: 85,
        headersOnly: false
    )