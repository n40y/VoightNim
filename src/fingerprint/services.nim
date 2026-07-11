## =============================================================================
## services.nim
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
