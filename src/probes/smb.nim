## ===============================================================================
## src/probes/smb.nim
## ===============================================================================

import ../fingerprint/types
import ../fingerprint/utils

# Payload SMB2 Negotiate Protocol (104 octets au total avec en-tête NetBIOS)
# Propose les dialectes SMB 2.0.2 et SMB 2.1
const Smb2NegotiatePayload*: seq[byte] = @[
  # En-tête NetBIOS Session (4 octets) : Type 0x00, Longueur 0x000068 (104 octets)
  byte 0x00, 0x00, 0x00, 0x68,

  # En-tête SMB2 (64 octets)
  0xfe, 0x53, 0x4d, 0x42, # Magic: \xFE SMB
  0x40, 0x00,             # Structure Size (64)
  0x00, 0x00,             # Credit Charge
  0x00, 0x00, 0x00, 0x00, # Status
  0x00, 0x00,             # Command: Negotiate (0)
  0x01, 0x00,             # Credit Request
  0x00, 0x00, 0x00, 0x00, # Flags
  0x00, 0x00, 0x00, 0x00, # Next Command
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # Message ID
  0x00, 0x00, 0x00, 0x00, # Process ID
  0x00, 0x00, 0x00, 0x00, # Tree ID
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # Session ID
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # Signature (16 octets)
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

  # Structure SMB2 Negotiate Request (36 octets)
  0x24, 0x00,             # Structure Size (36)
  0x02, 0x00,             # Dialect Count (2)
  0x01, 0x00,             # Security Mode (Signing Enabled)
  0x00, 0x00,             # Reserved
  0x00, 0x00, 0x00, 0x00, # Capabilities
  # Client GUID (16 octets nuls)
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, # NegotiateContextOffset / Count / Reserved
  0x02, 0x02,             # Dialect: SMB 2.0.2
  0x10, 0x02              # Dialect: SMB 2.1
]

proc createSmbProbe*(): ServiceProbe =
  result = ServiceProbe(
    name: "smb2_negotiate",
    probeType: ptSMB, # Remplacé par ptSMB
    transport: trTCP,
    ports: @[445.uint16, 139.uint16],
    payload: Smb2NegotiatePayload,
    timeoutMs: 1000
  )

proc parseSmbResponse*(data: string): tuple[matched: bool, banner: string] =
  ## Analyse la réponse brute du serveur SMB.
  if data.len < 8:
    return (false, "")

  # Vérification de la présence de la signature SMB2 (\xFE SMB) ou SMB1 (\xFF SMB)
  let bytes = toBytes(data)
  if bytes.len >= 8 and bytes[4] == 0xFE and bytes[5] == byte('S') and bytes[6] == byte('M') and bytes[7] == byte('B'):
    return (true, "SMBv2/v3 Protocol (Negotiate Response Received)")
  elif bytes.len >= 8 and bytes[4] == 0xFF and bytes[5] == byte('S') and bytes[6] == byte('M') and bytes[7] == byte('B'):
    return (true, "SMBv1 Protocol Supported")

  return (false, "")