# src/probes/ftp.nim

import ../fingerprint/types
import ../fingerprint/utils
import ../signatures/ftp/init as ftpSignatures

proc getFtpProbe*(): ServiceProbe =
  result = ServiceProbe(
    probeType: ptFTP,
    name: "FTP",
    payload: toBytes(""), # Vide pour gérer le Server Speaks First (attente du code 220)
    ports: @[21'u16],
    timeoutMs: 1000,
    rarity: 1,
    transport: trTCP,
    matches: ftpSignatures.getFtpSignatures()
  )