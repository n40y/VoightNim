import re2

import types

proc getSmtpProbe*(): ServiceProbe =
  result = ServiceProbe(
    name: "SMTP",

    payload: "EHLO scanner.local\r\n",

    ports: @[25, 465, 587],

    timeoutMs: 1500,

    rarity: 1,

    ssl: false
  )

  result.matches.add MatchRule(
    pattern: re2"Postfix",
    product: "Postfix",
    vendor: "Postfix",
    family: "Mail",
    cpe: "cpe:/a:postfix:postfix",
    versionGroup: 1,
    confidence: 100
  )

  result.matches.add MatchRule(
    pattern: re2"Exim",
    product: "Exim",
    vendor: "Exim",
    family: "Mail",
    cpe: "cpe:/a:exim:exim",
    versionGroup: 1,
    confidence: 100
  )

  result.matches.add MatchRule(
    pattern: re2"Microsoft ESMTP",
    product: "Exchange SMTP",
    vendor: "Microsoft",
    family: "Mail",
    cpe: "cpe:/a:microsoft:exchange_server",
    versionGroup: 1,
    confidence: 95
  )
