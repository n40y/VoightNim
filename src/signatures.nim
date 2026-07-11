# src/signatures.nim
#
# Base de signatures + identification de service, sur le même modèle
# async que prober.nim (asyncdispatch/asyncnet). Ce module s'appelle
# UNIQUEMENT sur un port déjà confirmé ouvert par scanRange.

import std/[asyncdispatch, asyncnet, nativesockets, strutils]
import regex

type
  MatchRule = object
    pattern: Regex2
    templateStr: string

  ServiceProbe = object
    name: string
    payload: string
    matches: seq[MatchRule]

# --- BASE DE DONNÉES DE SIGNATURES EMBARQUÉE (Ancien & Récent) ---
proc initSignatures(): seq[ServiceProbe] =
  # 1. NULL PROBE : on se connecte et on écoute immédiatement (bannières spontanées)
  var nullProbe = ServiceProbe(name: "NullProbe", payload: "", matches: @[])

  # Signatures SSH (Historique à Récent)
  nullProbe.matches.add(MatchRule(pattern: re2"^SSH-(\d\.\d)-OpenSSH_([\w.]+) ", templateStr: "OpenSSH v$2"))
  nullProbe.matches.add(MatchRule(pattern: re2"^SSH-(\d\.\d)-Dropbear_([\w.]+) ", templateStr: "Dropbear SSH v$2"))
  nullProbe.matches.add(MatchRule(pattern: re2"^SSH-1\.5-OpenSSH_2", templateStr: "Legacy OpenSSH 2.x (Vulnérable)"))
  nullProbe.matches.add(MatchRule(pattern: re2"OpenSSH_([\d.p]+)", templateStr: "OpenSSH $1"))
  nullProbe.matches.add(MatchRule(pattern: re2"libssh-([\d.]+)", templateStr: "libssh $1"))
  nullProbe.matches.add(MatchRule(pattern: re2"Cisco SSH-([\d.]+)", templateStr: "Cisco SSH $1"))
  nullProbe.matches.add(MatchRule(pattern: re2"Sun_SSH-([\d.]+)", templateStr: "SUNSSH $1"))


  # Signatures FTP (Ancien & Récent)
  nullProbe.matches.add(MatchRule(pattern: re2"^220.*vsFTPd (\d\.\d\.\d)", templateStr: "vsFTPd v$1"))
  nullProbe.matches.add(MatchRule(pattern: re2"^220.*ProFTPD (\d\.\d\.\d)", templateStr: "ProFTPD v$1"))
  nullProbe.matches.add(MatchRule(pattern: re2"^220.*Pure-FTPd", templateStr: "Pure-FTPd (Version Cachée)"))
  nullProbe.matches.add(MatchRule(pattern: re2"^220.*WarFTPd", templateStr: "WarFTPd (Legacy Windows)"))


  # Signatures SMTP / Courriel
  nullProbe.matches.add(MatchRule(pattern: re2"^220.*Postfix", templateStr: "Postfix SMTP"))
  nullProbe.matches.add(MatchRule(pattern: re2"^220.*Exim (\d\.\d\.\d)", templateStr: "Exim SMTP v$1"))
  nullProbe.matches.add(MatchRule(pattern: re2"^220.*Sendmail", templateStr: "Sendmail (Legacy)"))


  # Telnet & Divers
  nullProbe.matches.add(MatchRule(pattern: re2"(?i)login:\s*$", templateStr: "Telnet Service"))
  nullProbe.matches.add(MatchRule(pattern: re2"^AMQP\x00\x00\x09\x01", templateStr: "RabbitMQ / AMQP Broker"))


  # 2. HTTP PROBE : si le port est muet, on envoie une requête générique
  var httpProbe = ServiceProbe(
    name: "HTTPProbe",
    payload: "GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: VoightNim/1.0\r\nConnection: close\r\n\r\n",
    matches: @[]
  )


  # Redis sonde
  var redisProbe = ServiceProbe(
    name: "RedisProbe",
    payload:  "INFO\r\n",
    matches:  @[]
  )
  redisProbe.matches.add(MatchRule(pattern:  re2"redis_version:([\d.]+)", templateStr: "Redis v$1"))

  return @[nullProbe, httpProbe, redisProbe]


  # Serveurs Web Classiques & Modernes
  httpProbe.matches.add(MatchRule(pattern: re2"(?i)Server:\s*nginx/([\w.]+)", templateStr: "Nginx v$1"))
  httpProbe.matches.add(MatchRule(pattern: re2"(?i)Server:\s*Apache/([\w.]+) ", templateStr: "Apache HTTPD v$1"))
  httpProbe.matches.add(MatchRule(pattern: re2"(?i)Server:\s*cloudflare", templateStr: "Cloudflare Reverse Proxy"))
  httpProbe.matches.add(MatchRule(pattern: re2"(?i)Server:\s*Caddy", templateStr: "Caddy Server (Moderne Go)"))
  httpProbe.matches.add(MatchRule(pattern: re2"(?i)Server:\s*lighttpd/?([\d.]*)", templateStr: "Lighttpd $1"))
  httpProbe.matches.add(MatchRule(pattern: re2"(?i)Server:\s*gunicorn/?([\d.]*)"), templateStr: "Gunicorn $1")
  httpProbe.matches.add(MatchRule(pattern: re2"(?i)Server:\s*uvicorn", templateStr: "Uvicorn"))
  httpProbe.matches.add(MatchRule(pattern: re2"(?i)Server:\s*OpenResty/?([\d.]*)", templateStr: "OpenResty $1"))
  httpProbe.matches.add(MatchRule(pattern: re2"(?i)Server:\s*traefik", templateStr: "Traefik Proxy (Cloud Native)"))
  httpProbe.matches.add(MatchRule(pattern: re2"(?i)Server:\s*Envoy", templateStr: "Envoy Proxy"))
  httpProbe.matches.add(MatchRule(pattern: re2"(?i)Server:\s*Microsoft-IIS/([\w.]+)", templateStr: "Microsoft IIS v$1"))


  # Stacks Applicatives & Frameworks
  httpProbe.matches.add(MatchRule(pattern: re2"(?i)X-Powered-By:\s*Express", templateStr: "Node.js (Express Framework)"))
  httpProbe.matches.add(MatchRule(pattern: re2"(?i)Server:\s*Werkzeug/([\w.]+)", templateStr: "Python Werkzeug v$1 (Flask/API)"))
  httpProbe.matches.add(MatchRule(pattern: re2"(?i)X-Powered-By:\s*PHP/([875]\.[\w.]+)", templateStr: "PHP Engine v$1"))
  httpProbe.matches.add(MatchRule(pattern: re2"(?i)X-Powered-By:\s*PHP/([\d.]+)", templateStr: "PHP Engine v$1")
  httpProbe.matches.add(MatchRule(pattern: re2"(?i)Server:\s*Kestrel", templateStr: "Microsoft .NET Kestrel (Moderne)"))


  # ASP.NET
  httpProbe.matches.add(MatchRule(pattern:  re2"(?i)X-AspNet-Version:\s*([\d.]+)", templateStr: "X-AspNet-Version v$1"))
  return @[nullProbe, httpProbe]


# Chargée une seule fois, au chargement du module (évite de reconstruire
# la liste de regex à chaque appel d'identifyService)
let signatures = initSignatures()

# --- ANALYSE DE LA BANNIÈRE VIA REGEX ---
proc matchService(banner: string, probe: ServiceProbe): string =
  for rule in probe.matches:
    var m: RegexMatch2
    # find() cherche le motif n'importe où dans la bannière (pas besoin que
    # le motif consomme toute la chaîne, contrairement à match())
    if banner.find(rule.pattern, m):
      var resultStr = rule.templateStr
      # Décalage d'index : group(0) est le PREMIER groupe capturant (pas
      # "le match entier" comme en convention PCRE), donc group(i) correspond
      # à notre $(i+1) dans les templates.
      for i in 0 ..< 4:
        try:
          let bounds = m.group(i)
          # reNonCapture signale que ce groupe n'a pas participé au match
          # (règle avec moins de groupes que 4, ou groupe optionnel absent)
          if bounds != reNonCapture:
            let captured = banner[bounds]
            if captured.len > 0:
              resultStr = resultStr.replace("$" & $(i + 1), captured)
        except IndexDefect, RangeDefect:
          discard  # ce numéro de groupe n'existe pas du tout dans ce motif
      return resultStr
  return ""

# --- IDENTIFICATION ASYNC D'UN SERVICE ---
proc identifyService*(targetIP: string, port: int, timeoutMs: int = 1200): Future[string] {.async.} =
  ## À appeler uniquement sur un port déjà confirmé ouvert par scanRange.
  ## Ouvre une NOUVELLE connexion dédiée (celle du scan initial est déjà fermée).
  let socket = newAsyncSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, buffered = false)
  let connectFut = socket.connect(targetIP, Port(port))

  if not await withTimeout(connectFut, timeoutMs):
    socket.close()
    return "Inconnu (connexion impossible)"

  if connectFut.failed:
    discard connectFut.error
    socket.close()
    return "Inconnu (connexion refusée)"

  result = "Inconnu (pas de bannière identifiable)"

  for probe in signatures:
    try:
      if probe.payload.len > 0:
        await socket.send(probe.payload)

      let recvFut = socket.recv(2048)
      if not await withTimeout(recvFut, timeoutMs):
        continue  # rien reçu à temps sur cette sonde, on tente la suivante

      let banner = recvFut.read()
      if banner.len > 0:
        let matched = matchService(banner, probe)
        if matched.len > 0:
          result = matched
          break
        else:
          result = "Inconnu (bannière brute: " & banner.strip().replace("\r\n", " ") & ")"
    except OSError:
      break  # socket cassé côté distant, inutile d'insister avec la sonde suivante

  socket.close()
