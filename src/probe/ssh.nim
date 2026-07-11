import re2
import types

proc getSshProbe*(): ServiceProbe =
  result = ServiceProbe(
    name: "SSH",

    payload: "",

    ports: @[22],

    timeoutMs: 1000,

    rarity: 1,

    ssl: false
  )

  result.matches.add MatchRule(
    pattern: re2"OpenSSH[_-]([\d.p]+)",

    product: "OpenSSH",

    vendor: "OpenBSD",

    family: "Remote Access",

    cpe: "cpe:/a:openbsd:openssh",

    confidence: 100
  )

  result.matches.add MatchRule(
    pattern: re2"libssh-([\d.]+)",

    product: "libssh",

    vendor: "libssh",

    family: "Remote Access",

    cpe: "cpe:/a:libssh:libssh",

    confidence: 100
  )
