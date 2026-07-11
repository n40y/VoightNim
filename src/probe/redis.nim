import re2

import types

proc getRedisProbe*(): ServiceProbe =
  result = ServiceProbe(
    name: "Redis",

    payload: "INFO\r\n",

    ports: @[6379],

    timeoutMs: 1500,

    rarity: 1,

    ssl: false
  )

  result.matches.add MatchRule(
    pattern: re2"redis_version:([\d.]+)",

    product: "Redis",

    vendor: "Redis",

    family: "Database",

    cpe: "cpe:/a:redislabs:redis",

    confidence: 100
  )
