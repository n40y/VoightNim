# src/probes/ftp.nim

import ../fingerprint/types
import ../fingerprint/utils
import ../signatures/ftp/init as ftpSignatures

proc getFtpProbe*(): ServiceProbe =
  result = ServiceProbe(
    probeType: ptFTP,
    name: "FTP",
    payload: toBytes("USER anonymous\r\n"),
    ports: @[21'u16],
    timeoutMs: 1000,
    rarity: 1,
    ssl: false,
    matches: ftpSignatures.getFtpSignatures()
  )
