####################################################
##
## src/fingerprint/types.nim
##
####################################################

import regex

type
  ProbeType* = enum
    ptNull,
    ptHTTP,
    ptHTTPS,
    ptSSH,
    ptFTP,
    ptSMTP,
    ptPOP3,
    ptIMAP,
    ptLDAP,
    ptSMB,
    ptRDP,
    ptDNS,
    ptRedis,
    ptMySQL,
    ptPostgreSQL,
    ptMongoDB,
    ptMQTT,
    ptSNMP,
    ptMemcached,
    ptElastic,
    ptDocker

  ServiceId* = enum
    sidUnknown,

    ## Web servers
    sidNginx,
    sidApache,
    sidCaddy,
    sidLighttpd,
    sidOpenResty,
    sidIIS,

    ## Reverse Proxy / CDN
    sidCloudflare,
    sidTraefik,
    sidEnvoy,

    ## Application servers (WSGI/ASGI/.NET)
    sidGunicorn,
    sidUvicorn,
    sidKestrel,

    ## Runtime
    sidPHP,
    sidASPNet,
    sidNodeJS,

    ## Framework
    sidExpress,
    sidLaravel,
    sidDjango,
    sidFlask,

    ## SSH
    sidOpenSSH,
    sidLibSSH,
    sidDropbear,
    sidCiscoSSH,
    sidSunSSH,

    ## FTP
    sidVsftpd,
    sidProFTPd,
    sidFileZilla,
    sidPureFTPd,
    sidMicrosoftFTP,

    ## Mail
    sidPostfix,
    sidExim,
    sidExchange,
    sidSendmail,

    ## Databases
    sidRedis,
    sidMySQL,
    sidMariaDB,
    sidPostgreSQL,
    sidMongoDB,
    sidMemcached,

    ## LDAP
    sidOpenLDAP,
    sidActiveDirectory,

    ## Monitoring
    sidGrafana,
    sidPrometheus,
    sidElastic,

    ## Containers
    sidDocker,
    sidKubernetes,

    ## MQTT
    sidMosquitto,
    sidEMQX

  ServiceInfo* = object
    id*: ServiceId

    product*: string

    vendor*: string

    family*: string

    homepage*: string

    cpe*: string

    defaultPorts*: seq[uint16]

  MatchRule* = object
    pattern*: Regex2

    service*: ServiceId

    versionGroup*: int

    confidence*: uint8

    headersOnly*: bool  ## si true, la regex ne doit être testée que sur les
                         ## en-têtes HTTP (pas sur le corps de la réponse)

  Fingerprint* = object
    info*: ServiceInfo

    version*: string

    confidence*: uint8

    banner*: string

  OsFamily* = enum
    ofUnknown,
    ofLinux,
    ofWindows,
    ofBSD,
    ofMacOS

  OsId* = enum
    osUnknown,

    ## Linux
    osLinuxGeneric,
    osUbuntu,
    osDebian,
    osCentOS,
    osRHEL,
    osFedora,

    ## Windows
    osWindows,
    osWindowsServer,

    ## BSD
    osFreeBSD,
    osOpenBSD,

    ## macOS
    osMacOS

  OsInfo* = object
    id*: OsId

    name*: string

    family*: OsFamily

    cpe*: string

  OsMatchRule* = object
    pattern*: Regex2

    os*: OsId

    versionGroup*: int

    confidence*: uint8

    headersOnly*: bool

  OsFingerprint* = object
    info*: OsInfo

    version*: string

    confidence*: uint8

    banner*: string

  ServiceProbe* = ref object
    probeType*: ProbeType

    name*: string

    payload*: seq[byte]

    ports*: seq[uint16]

    ssl*: bool

    timeoutMs*: int

    rarity*: uint8

    matches*: seq[MatchRule]

    osMatches*: seq[OsMatchRule]