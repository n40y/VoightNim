# src/probes/ssh.nim

import ../fingerprint/types
import ../fingerprint/utils
import ../signatures/ssh/init as sshSignatures
import ../signatures/os/init as osSignatures
import ../fingerprint/proberegistry


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

# Auto-enregistrement : s'ajoute au registre global dès que ce module est
# importé (voir src/fingerprint/registry.nim). Rien d'autre n'a besoin de
# connaître explicitement cette sonde.
registerProbe(getSshProbe())