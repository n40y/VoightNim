## =======================================================
## src/syn/types.nim
## 
## Structures binaires pour le forgeage de paquets SYN
## =======================================================

type
  # Type utilitaire pour les pointeurs de calcul de checksum
  ptr16* = ptr uint16

  # Entête IPv4 Standard (20 octets)
  IpHeader* {.packed.} = object
    verIhl*: uint8       # Version (4 bits) + Internet Header Length (4 bits)
    tos*: uint8          # Type of Service
    totLen*: uint16      # Longueur totale (Header IP + Header TCP)
    id*: uint16          # Identification du fragment
    fragOff*: uint16     # Flags de fragmentation + Offset
    ttl*: uint8          # Time to Live
    protocol*: uint8     # Protocole (6 pour le TCP)
    check*: uint16       # Checksum de l'entête IP
    saddr*: uint32       # IP Source (Format binaire)
    daddr*: uint32       # IP Destination (Format binaire)

  # Entête TCP Standard (20 octets)
  TcpHeader* {.packed.} = object
    source*: uint16      # Port Source
    dest*: uint16        # Port Destination
    seq*: uint32         # Sequence Number
    ackSeq*: uint32      # Acknowledgment Number
    doffRes*: uint8      # Data Offset (4 bits) + Reserved (4 bits)
    flags*: uint8        # TCP Flags (ex: 0x02 pour le flag SYN)
    window*: uint16      # Taille de la fenêtre de réception
    check*: uint16       # Checksum TCP
    urgPtr*: uint16      # Urgent Pointer

  # Pseudo-en-tête requis uniquement pour le calcul du checksum TCP
  PseudoHeader* {.packed.} = object
    saddr*: uint32       # IP Source
    daddr*: uint32       # IP Destination
    reserved*: uint8     # Fixé à 0
    protocol*: uint8     # Protocole (6 pour le TCP)
    tcpLength*: uint16   # Longueur du bloc TCP (20 octets pour un SYN nu)