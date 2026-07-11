import types

import http
import ssh
import redis
import ftp
import smtp

proc getAllProbes*(): seq[ServiceProbe] =
    @[
        getHttpProbe(),
        getSshProbe(),
        getRedisProbe(),
        getFtpProbe(),
        getSmtpProbe(),
    ]
