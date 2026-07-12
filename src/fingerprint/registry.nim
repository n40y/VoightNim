# src/fingerprint/registry.nim
import types

import ../probes/http
import ../probes/ssh
import ../probes/redis
import ../probes/ftp
import ../probes/smtp

proc getAllProbes*(): seq[ServiceProbe] =
    @[
        getHttpProbe(),
        getSshProbe(),
        getRedisProbe(),
        getFtpProbe(),
        getSmtpProbe(),
    ]
