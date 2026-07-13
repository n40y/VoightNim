# src/probes/ssh.nim

import ../fingerprint/types
import ../fingerprint/utils
import ../signatures/ssh/init as sshSignatures
import ../signatures/os/init as osSignatures

proc getSshProbe*(): ServiceProbe =
  result = ServiceProbe(
    probeType: ptSSH,
    name: "SSH",
    payload: toBytes(""),
    ports: @[22'u16],
    timeoutMs: 1000,
    rarity: 1,
    transport: trTCP,
    matches: sshSignatures.getSshSignatures(),
    osMatches: osSignatures.getOsSignatures()
  )