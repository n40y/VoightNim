## =============================================================================
## signatures/msrpc/servers.nim
##
## Signatures des serveurs MSRPC.
## =============================================================================

import regex

import ../../fingerprint/types


proc getRpcEpmapServerSignatures*(): seq[MatchRule] =

    result = @[]

    result.add MatchRule(
        pattern: re2"^[\x05][\x00]",
        service: sidMSRPC_EPMAP,
        versionGroup: -1,
        confidence: 100,
        headersOnly: false
    )