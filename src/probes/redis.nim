# src/probes/redis.nim

import types
import utils
import ../signatures/redis/init as redisSignatures

proc getRedisProbe*(): ServiceProbe =
  result = ServiceProbe(
    probeType: ptRedis,
    name: "Redis",
    payload: toBytes("INFO\r\n"),
    ports: @[6379'u16],
    timeoutMs: 1500,
    rarity: 1,
    ssl: false,
    matches: redisSignatures.getRedisSignatures()
  )
