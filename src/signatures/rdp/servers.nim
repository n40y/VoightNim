## =============================================================================
## signatures/rdp/servers.nim
##
## Signatures pour le protocole RDP (Remote Desktop Protocol).
## =============================================================================


import regex
import ../../fingerprint/types


proc getRdpClassicSignatures*(): seq[MatchRule] =
    result = @[]

    # Détection d'un serveur RDP actif via la réponse COTP Connection Confirm (CC)
    # \x03\x00 (Header TPKT)  ... \x02\xf0\x80 (COTP Connection Confirm)

    result.add MatchRule(
        pattern: re2"^\x03\x00...\x02\xf0\x80",
        service: sidRDP,
        versionGroup: -1,
        confidence: 100,
        headersOnly: false  # Analyse le flux binaire brut, pas des en-têtes HTTP
    )