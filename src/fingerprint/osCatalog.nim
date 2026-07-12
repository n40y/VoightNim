## =============================================================================
## osCatalog.nim
##
## Base de connaissances des systèmes d'exploitation reconnus.
## Miroir de services.nim, mais pour l'axe OS plutôt que l'axe technologie.
## Toutes les signatures OS utilisent un OsId ; ce fichier est le seul
## endroit où sont décrits les OS eux-mêmes.
## =============================================================================

import ./types

proc getOs*(id: OsId): OsInfo =
  case id

  of osUnknown:
    OsInfo(id: osUnknown, name: "Unknown", family: ofUnknown, cpe: "")

  # ---------------------------------------------------------------------------
  # Linux
  # ---------------------------------------------------------------------------

  of osLinuxGeneric:
    OsInfo(
      id: osLinuxGeneric,
      name: "Linux",
      family: ofLinux,
      cpe: "cpe:/o:linux:linux_kernel"
    )

  of osUbuntu:
    OsInfo(
      id: osUbuntu,
      name: "Ubuntu",
      family: ofLinux,
      cpe: "cpe:/o:canonical:ubuntu_linux"
    )

  of osDebian:
    OsInfo(
      id: osDebian,
      name: "Debian",
      family: ofLinux,
      cpe: "cpe:/o:debian:debian_linux"
    )

  of osCentOS:
    OsInfo(
      id: osCentOS,
      name: "CentOS",
      family: ofLinux,
      cpe: "cpe:/o:centos:centos"
    )

  of osRHEL:
    OsInfo(
      id: osRHEL,
      name: "Red Hat Enterprise Linux",
      family: ofLinux,
      cpe: "cpe:/o:redhat:enterprise_linux"
    )

  of osFedora:
    OsInfo(
      id: osFedora,
      name: "Fedora",
      family: ofLinux,
      cpe: "cpe:/o:fedoraproject:fedora"
    )

  # ---------------------------------------------------------------------------
  # Windows
  # ---------------------------------------------------------------------------

  of osWindows:
    OsInfo(
      id: osWindows,
      name: "Windows",
      family: ofWindows,
      cpe: "cpe:/o:microsoft:windows"
    )

  of osWindowsServer:
    OsInfo(
      id: osWindowsServer,
      name: "Windows Server",
      family: ofWindows,
      cpe: "cpe:/o:microsoft:windows_server"
    )

  # ---------------------------------------------------------------------------
  # BSD
  # ---------------------------------------------------------------------------

  of osFreeBSD:
    OsInfo(
      id: osFreeBSD,
      name: "FreeBSD",
      family: ofBSD,
      cpe: "cpe:/o:freebsd:freebsd"
    )

  of osOpenBSD:
    OsInfo(
      id: osOpenBSD,
      name: "OpenBSD",
      family: ofBSD,
      cpe: "cpe:/o:openbsd:openbsd"
    )

  # ---------------------------------------------------------------------------
  # macOS
  # ---------------------------------------------------------------------------

  of osMacOS:
    OsInfo(
      id: osMacOS,
      name: "macOS",
      family: ofMacOS,
      cpe: "cpe:/o:apple:macos"
    )
