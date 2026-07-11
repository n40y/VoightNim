import re2

import ../types

proc getHttpSignatures*(): seq[MatchRule] =

  result = @[]

  #
  # Web Servers
  #

  result.add MatchRule(
    pattern: re2"(?i)Server:\s*nginx/?([\d.]*)",
    service: sidNginx,
    versionGroup: 1,
    confidence: 100,
    headersOnly: true
  )

  result.add MatchRule(
    pattern: re2"(?i)Server:\s*Apache/?([\d.]*)",
    service: sidApache,
    versionGroup: 1,
    confidence: 100,
    headersOnly: true
  )

  result.add MatchRule(
    pattern: re2"(?i)Server:\s*Caddy",
    service: sidCaddy,
    versionGroup: 0,
    confidence: 100,
    headersOnly: true
  )

  result.add MatchRule(
    pattern: re2"(?i)Server:\s*lighttpd/?([\d.]*)",
    service: sidLighttpd,
    versionGroup: 1,
    confidence: 100,
    headersOnly: true
  )

  result.add MatchRule(
    pattern: re2"(?i)Server:\s*OpenResty/?([\d.]*)",
    service: sidOpenResty,
    versionGroup: 1,
    confidence: 100,
    headersOnly: true
  )

  result.add MatchRule(
    pattern: re2"(?i)Server:\s*Microsoft-IIS/?([\d.]*)",
    service: sidIIS,
    versionGroup: 1,
    confidence: 100,
    headersOnly: true
  )

  #
  # Runtime
  #

  result.add MatchRule(
    pattern: re2"(?i)X-Powered-By:\s*PHP/?([\d.]*)",
    service: sidPHP,
    versionGroup: 1,
    confidence: 95,
    headersOnly: true
  )

  result.add MatchRule(
    pattern: re2"(?i)X-Powered-By:\s*ASP\.NET",
    service: sidASPNet,
    versionGroup: 0,
    confidence: 95,
    headersOnly: true
  )

  result.add MatchRule(
    pattern: re2"(?i)X-Powered-By:\s*Express",
    service: sidExpress,
    versionGroup: 0,
    confidence: 95,
    headersOnly: true
  )

  #
  # Frameworks
  #

  result.add MatchRule(
    pattern: re2"(?i)laravel_session",
    service: sidLaravel,
    versionGroup: 0,
    confidence: 90,
    headersOnly: false
  )

  result.add MatchRule(
    pattern: re2"(?i)csrftoken",
    service: sidDjango,
    versionGroup: 0,
    confidence: 90,
    headersOnly: false
  )

  result.add MatchRule(
    pattern: re2"(?i)Werkzeug",
    service: sidFlask,
    versionGroup: 0,
    confidence: 90,
    headersOnly: false
  )

  #
  # Monitoring
  #

  result.add MatchRule(
    pattern: re2"(?i)X-Grafana-Version:\s*([\d.]+)",
    service: sidGrafana,
    versionGroup: 1,
    confidence: 100,
    headersOnly: true
  )

  result.add MatchRule(
    pattern: re2"(?i)kbn-name",
    service: sidElastic,
    versionGroup: 0,
    confidence: 90,
    headersOnly: true
  )

  result.add MatchRule(
    pattern: re2"(?i)Prometheus",
    service: sidPrometheus,
    versionGroup: 0,
    confidence: 85,
    headersOnly: false
  )
