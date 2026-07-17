# src/probes/smtp.nim

import ../fingerprint/types
import ../fingerprint/utils
import ../signatures/smtp/init as smtpSignatures
import ../fingerprint/proberegistry


proc getSmtpProbe*(): ServiceProbe =
  result = ServiceProbe(
    probeType: ptSMTP,
    name: "SMTP",
    payload: toBytes(""), # Vide pour chasser la bannière d'accueil avant d'envoyer un EHLO
    ports: @[25'u16, 465'u16, 587'u16],
    timeoutMs: 1500,
    rarity: 1,
    transport: trTCP,
    matches: smtpSignatures.getSmtpSignatures()
  )

# Auto-enregistrement : s'ajoute au registre global dès que ce module est
# importé (voir src/fingerprint/registry.nim). Rien d'autre n'a besoin de
# connaître explicitement cette sonde.
registerProbe(getSmtpProbe())