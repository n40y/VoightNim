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
    ptLDAPS,
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
    ptDocker,
    ptKerberos,
    ptRPC,
    ptNTP,
    ptVNC

  Transport* = enum 
    trTCP,
    trUDP,
    trTLS

  ServiceId* = enum
    sidUnknown,

    ## -------------------------
    ## RDP
    ## -------------------------
    sidRDP,

    ## -------------------------
    ## HTTP
    ## -------------------------
    sidNginx,
    sidApache,
    sidCaddy,
    sidLighttpd,
    sidOpenResty,
    sidIIS,
    
    ## -------------------------
    ## Ajouts récents
    ## -------------------------
    sidMSRPC,         # Microsoft RPC over HTTP
    sidMSRPC_EPMAP,   # Microsoft RPC Endpoint Mapper (Port 135)
    sidMicrosoftDNS,  # Micreosoft DNS Service (Port 53)
    sidADWS,          # Active Directory Web Services 
    
    ## Reverse Proxy
    sidCloudflare,
    sidTraefik,
    sidEnvoy,
    sidHAProxy,

    ## Runtime
    sidGunicorn,
    sidUvicorn,
    sidKestrel,
    sidPHP,
    sidASPNet,
    sidNodeJS,

    ## Frameworks
    sidExpress,
    sidLaravel,
    sidDjango,
    sidFlask,

    ## -------------------------
    ## SSH
    ## -------------------------
    sidOpenSSH,
    sidLibSSH,
    sidDropbear,
    sidCiscoSSH,
    sidSunSSH,

    ## -------------------------
    ## FTP
    ## -------------------------
    sidVsftpd,
    sidProFTPd,
    sidFileZilla,
    sidPureFTPd,
    sidMicrosoftFTP,

    ## -------------------------
    ## SMTP
    ## -------------------------
    sidPostfix,
    sidExim,
    sidExchange,
    sidSendmail,

    ## -------------------------
    ## Databases
    ## -------------------------
    sidRedis,
    sidMySQL,
    sidMariaDB,
    sidPostgreSQL,
    sidMongoDB,
    sidMemcached,

    ## -------------------------
    ## LDAP
    ## -------------------------
    sidLDAP,
    sidOpenLDAP,
    sidActiveDirectory,
    sidApacheDS,
    sid389DirectoryServer,
    sidRedHatDirectoryServer,
    sidOpenDJ,
    sidOpenDS,
    sidOracleUnifiedDirectory,
    sidIBMSecurityDirectoryServer,
    sidForgeRockDS,

    ## -------------------------
    ## SMB
    ## -------------------------
    sidSamba,
    sidWindowsSMB,
    sidSMB20,
    sidSMB21,
    sidSMB30,
    sidSMB311,
    sidSynologyDSM,
    sidTrueNAS,
    sidNetApp,
    sidQNAP,

    ## -------------------------
    ## Kerberos
    ## -------------------------
    sidKerberos,
    sidMITKerberos,
    sidHeimdal,
    sidMicrosoftKerberos,
    sidFreeIPA,
    sidSambaKerberos,

    ## -------------------------
    ## Monitoring
    ## -------------------------
    sidGrafana,
    sidPrometheus,
    sidElastic,

    ## -------------------------
    ## Containers
    ## -------------------------
    sidDocker,
    sidKubernetes,

    ## -------------------------
    ## MQTT
    ## -------------------------
    sidMosquitto,
    sidEMQX


  ServiceInfo* = object
    id*: ServiceId
    protocol*: ProbeType
    product*: string
    vendor*: string
    family*: string
    homepage*: string
    cpe*: string
    defaultPorts*: seq[uint16]


  MatchRule* = object
    pattern*:         Regex2
    service*:         ServiceId
    versionGroup*:    int
    confidence*:      uint8
    headersOnly*:     bool  ## si true, la regex ne doit être testée que sur les
                         ## en-têtes HTTP (pas sur le corps de la réponse)


  Fingerprint* = object
    info*: ServiceInfo
    version*:     string
    confidence*:  uint8
    banner*:      string
    score*:       float32


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
    description*: string
    name*: string
    payload*: seq[byte]
    ports*: seq[uint16]
    fallbackPorts*: seq[uint16]
    transport*: Transport
    timeoutMs*: int
    rarity*: uint8
    matches*: seq[MatchRule]
    osMatches*: seq[OsMatchRule]
    # ajoutés
    enabled*: bool
    maxPayloadSize*: int
