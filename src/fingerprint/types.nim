import re2

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

    ## FTP
    sidVsftpd,
    sidProFTPd,
    sidFileZilla,

    ## Mail
    sidPostfix,
    sidExim,
    sidExchange,

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

  Fingerprint* = object
    info*: ServiceInfo

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
