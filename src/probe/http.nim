import re2

import types

proc getHttpProbe*(): ServiceProbe =
  result = ServiceProbe(
    name: "HTTP",
    payload: "GET / HTTP/1.0\r\n\r\n",

    ports: @[80, 8080, 8000, 8888],

    timeoutMs: 1000,

    rarity: 1,

    ssl: false
  )

  result.matches.add MatchRule(
  pattern: re2"(?i)Server:\s*nginx/?([\d.]*)",
  product: "nginx",
  vendor: "Nginx",
  family: "Web Server",
  cpe: "cpe:/a:nginx:nginx",
  versionGroup: 1,
  confidence: 100
  )

  result.matches.add MatchRule(
    pattern: re2"(?i)Server:\s*Apache/?([\d.]*)",
    product: "Apache HTTPD",
    vendor: "Apache",
    family: "Web Server",
    cpe: "cpe:/a:apache:http_server",
    versionGroup: 1,
    confidence: 100
  )

  result.matches.add MatchRule(
    pattern: re2"(?i)Server:\s*Caddy",
    product: "Caddy",
    vendor: "Caddy",
    family: "Web Server",
    cpe: "cpe:/a:caddyserver:caddy",
    versionGroup: 1,
    confidence: 100
  )

  result.matches.add MatchRule(
    pattern: re2"(?i)X-Powered-By:\s*PHP",
    product: "PHP",
    vendor: "PHP",
    family: "Runtime",
    cpe: "cpe:/a:php:php",
    versionGroup: 1,
    confidence: 90
  )

  result.matches.add MatchRule(
    pattern: re2"(?i)X-Powered-By:\s*Express",
    product: "Express",
    vendor: "ExpressJS",
    family: "Framework",
    cpe: "cpe:/a:expressjs:express",
    versionGroup: 1,
    confidence: 95
  )
