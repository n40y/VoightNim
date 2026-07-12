## =============================================================================
## src/fingerprint/services.nim
##
## Base de connaissances des technologies reconnues.
##
## Toutes les signatures utilisent un ServiceId.
## Ce fichier est le seul endroit où sont décrites les technologies.
##
## =============================================================================

import ./types

proc getService*(id: ServiceId): ServiceInfo =
  case id

  of sidUnknown:
    ServiceInfo(
      id: sidUnknown,
      product: "Unknown",
      vendor: "",
      family: "",
      homepage: "",
      cpe: "",
      defaultPorts: @[]
    )

  # ---------------------------------------------------------------------------
  # Web servers
  # ---------------------------------------------------------------------------

  of sidNginx:
    ServiceInfo(
      id: sidNginx,
      product: "nginx",
      vendor: "F5",
      family: "Web Server",
      homepage: "https://nginx.org",
      cpe: "cpe:/a:nginx:nginx",
      defaultPorts: @[80'u16, 443'u16]
    )

  of sidApache:
    ServiceInfo(
      id: sidApache,
      product: "Apache HTTP Server",
      vendor: "Apache Software Foundation",
      family: "Web Server",
      homepage: "https://httpd.apache.org",
      cpe: "cpe:/a:apache:http_server",
      defaultPorts: @[80'u16, 443'u16]
    )

  of sidCaddy:
    ServiceInfo(
      id: sidCaddy,
      product: "Caddy",
      vendor: "Caddy",
      family: "Web Server",
      homepage: "https://caddyserver.com",
      cpe: "cpe:/a:caddy:caddy",
      defaultPorts: @[80'u16,443'u16]
    )

  of sidLighttpd:
    ServiceInfo(
      id: sidLighttpd,
      product: "lighttpd",
      vendor: "lighttpd",
      family: "Web Server",
      homepage: "https://www.lighttpd.net",
      cpe: "cpe:/a:lighttpd:lighttpd",
      defaultPorts: @[80'u16,443'u16]
    )

  of sidOpenResty:
    ServiceInfo(
      id: sidOpenResty,
      product: "OpenResty",
      vendor: "OpenResty",
      family: "Web Server",
      homepage: "https://openresty.org",
      cpe: "cpe:/a:openresty:openresty",
      defaultPorts: @[80'u16,443'u16]
    )

  of sidIIS:
    ServiceInfo(
      id: sidIIS,
      product: "Microsoft IIS",
      vendor: "Microsoft",
      family: "Web Server",
      homepage: "https://learn.microsoft.com/iis/",
      cpe: "cpe:/a:microsoft:internet_information_services",
      defaultPorts: @[80'u16,443'u16]
    )

  # ---------------------------------------------------------------------------
  # Reverse Proxy / CDN
  # ---------------------------------------------------------------------------

  of sidCloudflare:
    ServiceInfo(
      id: sidCloudflare,
      product: "Cloudflare",
      vendor: "Cloudflare",
      family: "Reverse Proxy",
      homepage: "https://cloudflare.com",
      cpe: "",
      defaultPorts: @[80'u16, 443'u16]
    )

  of sidTraefik:
    ServiceInfo(
      id: sidTraefik,
      product: "Traefik",
      vendor: "Traefik Labs",
      family: "Reverse Proxy",
      homepage: "https://traefik.io",
      cpe: "cpe:/a:traefik:traefik",
      defaultPorts: @[80'u16, 443'u16, 8080'u16]
    )

  of sidEnvoy:
    ServiceInfo(
      id: sidEnvoy,
      product: "Envoy",
      vendor: "Envoy Proxy",
      family: "Reverse Proxy",
      homepage: "https://envoyproxy.io",
      cpe: "cpe:/a:envoyproxy:envoy",
      defaultPorts: @[80'u16, 443'u16]
    )

  # ---------------------------------------------------------------------------
  # Application servers (WSGI/ASGI/.NET)
  # ---------------------------------------------------------------------------

  of sidGunicorn:
    ServiceInfo(
      id: sidGunicorn,
      product: "Gunicorn",
      vendor: "Gunicorn",
      family: "Application Server",
      homepage: "https://gunicorn.org",
      cpe: "cpe:/a:gunicorn:gunicorn",
      defaultPorts: @[8000'u16]
    )

  of sidUvicorn:
    ServiceInfo(
      id: sidUvicorn,
      product: "Uvicorn",
      vendor: "Uvicorn",
      family: "Application Server",
      homepage: "https://www.uvicorn.org",
      cpe: "",
      defaultPorts: @[8000'u16]
    )

  of sidKestrel:
    ServiceInfo(
      id: sidKestrel,
      product: "Kestrel",
      vendor: "Microsoft",
      family: "Application Server",
      homepage: "https://learn.microsoft.com/aspnet/core/fundamentals/servers/kestrel",
      cpe: "cpe:/a:microsoft:asp.net_core",
      defaultPorts: @[5000'u16, 5001'u16]
    )

  # ---------------------------------------------------------------------------
  # Runtime
  # ---------------------------------------------------------------------------

  of sidPHP:
    ServiceInfo(
      id: sidPHP,
      product: "PHP",
      vendor: "PHP Group",
      family: "Runtime",
      homepage: "https://php.net",
      cpe: "cpe:/a:php:php",
      defaultPorts: @[]
    )

  of sidASPNet:
    ServiceInfo(
      id: sidASPNet,
      product: "ASP.NET",
      vendor: "Microsoft",
      family: "Runtime",
      homepage: "https://dotnet.microsoft.com",
      cpe: "cpe:/a:microsoft:asp.net",
      defaultPorts: @[]
    )

  of sidNodeJS:
    ServiceInfo(
      id: sidNodeJS,
      product: "Node.js",
      vendor: "OpenJS Foundation",
      family: "Runtime",
      homepage: "https://nodejs.org",
      cpe: "cpe:/a:nodejs:node.js",
      defaultPorts: @[]
    )

  # ---------------------------------------------------------------------------
  # Frameworks
  # ---------------------------------------------------------------------------

  of sidExpress:
    ServiceInfo(
      id: sidExpress,
      product: "Express",
      vendor: "OpenJS Foundation",
      family: "Framework",
      homepage: "https://expressjs.com",
      cpe: "cpe:/a:expressjs:express",
      defaultPorts: @[]
    )

  of sidLaravel:
    ServiceInfo(
      id: sidLaravel,
      product: "Laravel",
      vendor: "Laravel",
      family: "Framework",
      homepage: "https://laravel.com",
      cpe: "cpe:/a:laravel:laravel",
      defaultPorts: @[]
    )

  of sidDjango:
    ServiceInfo(
      id: sidDjango,
      product: "Django",
      vendor: "Django Software Foundation",
      family: "Framework",
      homepage: "https://djangoproject.com",
      cpe: "cpe:/a:djangoproject:django",
      defaultPorts: @[]
    )

  of sidFlask:
    ServiceInfo(
      id: sidFlask,
      product: "Flask",
      vendor: "Pallets",
      family: "Framework",
      homepage: "https://flask.palletsprojects.com",
      cpe: "cpe:/a:palletsprojects:flask",
      defaultPorts: @[]
    )

  # ---------------------------------------------------------------------------
  # SSH
  # ---------------------------------------------------------------------------

  of sidOpenSSH:
    ServiceInfo(
      id: sidOpenSSH,
      product: "OpenSSH",
      vendor: "OpenBSD",
      family: "Remote Access",
      homepage: "https://openssh.com",
      cpe: "cpe:/a:openbsd:openssh",
      defaultPorts: @[22'u16]
    )

  of sidLibSSH:
    ServiceInfo(
      id: sidLibSSH,
      product: "libssh",
      vendor: "libssh",
      family: "Remote Access",
      homepage: "https://libssh.org",
      cpe: "cpe:/a:libssh:libssh",
      defaultPorts: @[22'u16]
    )

  of sidDropbear:
    ServiceInfo(
      id: sidDropbear,
      product: "Dropbear SSH",
      vendor: "Dropbear",
      family: "Remote Access",
      homepage: "https://matt.ucc.asn.au/dropbear/dropbear.html",
      cpe: "cpe:/a:matt_johnston:dropbear_ssh_server",
      defaultPorts: @[22'u16]
    )

  of sidCiscoSSH:
    ServiceInfo(
      id: sidCiscoSSH,
      product: "Cisco SSH",
      vendor: "Cisco",
      family: "Remote Access",
      homepage: "https://cisco.com",
      cpe: "",
      defaultPorts: @[22'u16]
    )

  of sidSunSSH:
    ServiceInfo(
      id: sidSunSSH,
      product: "SunSSH",
      vendor: "Oracle/Sun",
      family: "Remote Access",
      homepage: "",
      cpe: "",
      defaultPorts: @[22'u16]
    )

  # ---------------------------------------------------------------------------
  # FTP
  # ---------------------------------------------------------------------------

  of sidVsftpd:
    ServiceInfo(
      id: sidVsftpd,
      product: "vsftpd",
      vendor: "vsftpd",
      family: "FTP",
      homepage: "https://security.appspot.com/vsftpd.html",
      cpe: "cpe:/a:vsftpd_project:vsftpd",
      defaultPorts: @[21'u16]
    )

  of sidProFTPd:
    ServiceInfo(
      id: sidProFTPd,
      product: "ProFTPD",
      vendor: "ProFTPD Project",
      family: "FTP",
      homepage: "https://proftpd.org",
      cpe: "cpe:/a:proftpd:proftpd",
      defaultPorts: @[21'u16]
    )

  of sidFileZilla:
    ServiceInfo(
      id: sidFileZilla,
      product: "FileZilla Server",
      vendor: "FileZilla",
      family: "FTP",
      homepage: "https://filezilla-project.org",
      cpe: "cpe:/a:filezilla:filezilla_server",
      defaultPorts: @[21'u16]
    )

  of sidPureFTPd:
    ServiceInfo(
      id: sidPureFTPd,
      product: "Pure-FTPd",
      vendor: "Pure-FTPd",
      family: "FTP",
      homepage: "https://pureftpd.org",
      cpe: "cpe:/a:pureftpd:pure-ftpd",
      defaultPorts: @[21'u16]
    )

  of sidMicrosoftFTP:
    ServiceInfo(
      id: sidMicrosoftFTP,
      product: "Microsoft FTP Service",
      vendor: "Microsoft",
      family: "FTP",
      homepage: "",
      cpe: "cpe:/a:microsoft:ftp_service",
      defaultPorts: @[21'u16]
    )

  # ---------------------------------------------------------------------------
  # Mail
  # ---------------------------------------------------------------------------

  of sidPostfix:
    ServiceInfo(
      id: sidPostfix,
      product: "Postfix",
      vendor: "Postfix",
      family: "Mail",
      homepage: "https://postfix.org",
      cpe: "cpe:/a:postfix:postfix",
      defaultPorts: @[25'u16, 587'u16]
    )

  of sidExim:
    ServiceInfo(
      id: sidExim,
      product: "Exim",
      vendor: "Exim",
      family: "Mail",
      homepage: "https://exim.org",
      cpe: "cpe:/a:exim:exim",
      defaultPorts: @[25'u16]
    )

  of sidExchange:
    ServiceInfo(
      id: sidExchange,
      product: "Microsoft Exchange",
      vendor: "Microsoft",
      family: "Mail",
      homepage: "https://microsoft.com/exchange",
      cpe: "cpe:/a:microsoft:exchange_server",
      defaultPorts: @[25'u16, 587'u16]
    )

  of sidSendmail:
    ServiceInfo(
      id: sidSendmail,
      product: "Sendmail",
      vendor: "Proofpoint",
      family: "Mail",
      homepage: "https://proofpoint.com/us/products/email-protection/open-source-email-solution",
      cpe: "cpe:/a:sendmail:sendmail",
      defaultPorts: @[25'u16]
    )

  # ---------------------------------------------------------------------------
  # Monitoring
  # ---------------------------------------------------------------------------

  of sidGrafana:
    ServiceInfo(
      id: sidGrafana,
      product: "Grafana",
      vendor: "Grafana Labs",
      family: "Monitoring",
      homepage: "https://grafana.com",
      cpe: "cpe:/a:grafana:grafana",
      defaultPorts: @[3000'u16]
    )

  of sidPrometheus:
    ServiceInfo(
      id: sidPrometheus,
      product: "Prometheus",
      vendor: "Prometheus",
      family: "Monitoring",
      homepage: "https://prometheus.io",
      cpe: "cpe:/a:prometheus:prometheus",
      defaultPorts: @[9090'u16]
    )

  of sidElastic:
    ServiceInfo(
      id: sidElastic,
      product: "Elasticsearch/Kibana",
      vendor: "Elastic",
      family: "Monitoring",
      homepage: "https://elastic.co",
      cpe: "cpe:/a:elastic:elasticsearch",
      defaultPorts: @[9200'u16, 5601'u16]
    )

  # ---------------------------------------------------------------------------
  # Databases
  # ---------------------------------------------------------------------------

  of sidRedis:
    ServiceInfo(
      id: sidRedis,
      product: "Redis",
      vendor: "Redis",
      family: "Database",
      homepage: "https://redis.io",
      cpe: "cpe:/a:redislabs:redis",
      defaultPorts: @[6379'u16]
    )

  of sidMySQL:
    ServiceInfo(
      id: sidMySQL,
      product: "MySQL",
      vendor: "Oracle",
      family: "Database",
      homepage: "https://mysql.com",
      cpe: "cpe:/a:mysql:mysql",
      defaultPorts: @[3306'u16]
    )

  of sidMariaDB:
    ServiceInfo(
      id: sidMariaDB,
      product: "MariaDB",
      vendor: "MariaDB Foundation",
      family: "Database",
      homepage: "https://mariadb.org",
      cpe: "cpe:/a:mariadb:mariadb",
      defaultPorts: @[3306'u16]
    )

  of sidPostgreSQL:
    ServiceInfo(
      id: sidPostgreSQL,
      product: "PostgreSQL",
      vendor: "PostgreSQL Global Development Group",
      family: "Database",
      homepage: "https://postgresql.org",
      cpe: "cpe:/a:postgresql:postgresql",
      defaultPorts: @[5432'u16]
    )

  of sidMongoDB:
    ServiceInfo(
      id: sidMongoDB,
      product: "MongoDB",
      vendor: "MongoDB",
      family: "Database",
      homepage: "https://mongodb.com",
      cpe: "cpe:/a:mongodb:mongodb",
      defaultPorts: @[27017'u16]
    )

  else:
    ServiceInfo(
      id: id,
      product: "Unknown",
      vendor: "",
      family: "",
      homepage: "",
      cpe: "",
      defaultPorts: @[]
    )
