## =============================================================================
## signatures/http/webservers.nim
##
## Signatures pour les serveurs web et reverse proxies détectés via les
## en-têtes HTTP (principalement l'en-tête Server:).
##
## Toutes ces règles utilisent headersOnly: true car ces informations
## proviennent exclusivement des en-têtes, jamais du corps de la réponse.
## =============================================================================

import regex

import ../../fingerprint/types

proc getWebServerSignatures*(): seq[MatchRule] =

  result = @[]

  # ---------------------------------------------------------------------------
  # Composants d'infrastructure Microsoft (RPC / Active Directory)
  # ---------------------------------------------------------------------------

  # Pour le Port 593 (MSRPC over HTTP)
  result.add MatchRule(
    pattern: re2(r"(?s).*ncacn_http/([\d.]+).*"), # Le préfixe r"" protège les \d. (?s) active le mode DotAll (le . matche aussi les retours à la ligne).
    service: sidMSRPC,
    versionGroup: 1,                             # Groupe 1 correspond bien à ([\d.]+)
    confidence: 100,
    headersOnly: false
  )

  # Pour le Port 9389 (ADWS)
  result.add MatchRule(
    pattern: re2(r"(?s).*schemas\.microsoft\.com/ws/2006/05/framing.*"), # Protection du point avec \. valide
    service: sidADWS,
    versionGroup: -1,
    confidence: 100,
    headersOnly: false
  )

  # ---------------------------------------------------------------------------
  # Serveurs web classiques
  # ---------------------------------------------------------------------------

  result.add MatchRule(
    pattern: re2"(?i)Server:\s*nginx(?:/([\d.]+))?",
    service: sidNginx,
    versionGroup: 0,
    confidence: 100,
    headersOnly: true
  )

  result.add MatchRule(
    pattern: re2"(?i)Server:\s*Apache(?:/([\d.]+))?",
    service: sidApache,
    versionGroup: 0,
    confidence: 100,
    headersOnly: true
  )

  result.add MatchRule(
    pattern: re2"(?i)Server:\s*Caddy",
    service: sidCaddy,
    versionGroup: -1,
    confidence: 100,
    headersOnly: true
  )

  result.add MatchRule(
    pattern: re2"(?i)Server:\s*lighttpd(?:/([\d.]+))?",
    service: sidLighttpd,
    versionGroup: 0,
    confidence: 100,
    headersOnly: true
  )

  result.add MatchRule(
    pattern: re2"(?i)Server:\s*OpenResty(?:/([\d.]+))?",
    service: sidOpenResty,
    versionGroup: 0,
    confidence: 100,
    headersOnly: true
  )

  result.add MatchRule(
    pattern: re2"(?i)Server:\s*Microsoft-IIS(?:/([\d.]+))?",
    service: sidIIS,
    versionGroup: 0,
    confidence: 100,
    headersOnly: true
  )

  # ---------------------------------------------------------------------------
  # Reverse proxies / CDN
  # ---------------------------------------------------------------------------

  result.add MatchRule(
    pattern: re2"(?i)Server:\s*cloudflare",
    service: sidCloudflare,
    versionGroup: -1,
    confidence: 100,
    headersOnly: true
  )

  result.add MatchRule(
    pattern: re2"(?i)Server:\s*traefik",
    service: sidTraefik,
    versionGroup: -1,
    confidence: 95,
    headersOnly: true
  )

  result.add MatchRule(
    pattern: re2"(?i)Server:\s*envoy",
    service: sidEnvoy,
    versionGroup: -1,
    confidence: 95,
    headersOnly: true
  )

  # ---------------------------------------------------------------------------
  # Serveurs d'application WSGI/ASGI/.NET
  # ---------------------------------------------------------------------------

  result.add MatchRule(
    pattern: re2"(?i)Server:\s*gunicorn(?:/([\d.]+))?",
    service: sidGunicorn,
    versionGroup: 0,
    confidence: 95,
    headersOnly: true
  )

  result.add MatchRule(
    pattern: re2"(?i)Server:\s*uvicorn",
    service: sidUvicorn,
    versionGroup: -1,
    confidence: 95,
    headersOnly: true
  )

  result.add MatchRule(
    pattern: re2"(?i)Server:\s*Kestrel",
    service: sidKestrel,
    versionGroup: -1,
    confidence: 95,
    headersOnly: true
  )
