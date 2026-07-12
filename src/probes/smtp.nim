# src/probes/smtp.nim

import ../fingerprint/types
import ../fingerprint/utils
import ../signatures/smtp/init as smtpSignatures

proc getSmtpProbe*(): ServiceProbe =
  result = ServiceProbe(
    probeType: ptSMTP,
    name: "SMTP",
    payload: toBytes("EHLO scanner.local\r\n"),
    ports: @[25'u16, 465'u16, 587'u16],
    timeoutMs: 1500,
    rarity: 1,
    ssl: false,
    matches: smtpSignatures.getSmtpSignatures()
  )