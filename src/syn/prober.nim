## =======================================================
## src/syn/prober.nim
## 
## Logique d'assemblage et aiguillage multiplateforme épuré
## =======================================================

import std/[nativesockets, os, strutils]
import ./types, ./checksum

type
  # Buffer contigu temporaire combinant les deux en-têtes pour le checksum TCP
  TcpChecksumBuffer {.packed.} = object
    pseudo: PseudoHeader
    tcp: TcpHeader


# Convertit une chaîne IP (ex: "192.168.1.1") en uint32 binaire (Network Byte Order)
proc ipToUint32(ipStr: string): uint32 =
  let parts = ipStr.split('.')
  if parts.len == 4:
    let o1 = cast[uint32](parseInt(parts[0]))
    let o2 = cast[uint32](parseInt(parts[1]))
    let o3 = cast[uint32](parseInt(parts[2]))
    let o4 = cast[uint32](parseInt(parts[3]))
    
    let hostUint = (o1 shl 24) or (o2 shl 16) or (o3 shl 8) or o4
    result = htonl(hostUint)
  else:
    result = 0


# --- Aiguillage des modules bas-niveau par OS ---
when defined(windows):
  import ./win_pcap
elif defined(linux):
  import ./linux_raw


proc sendSynPacket*(srcIp: string, destIp: string, srcPort: uint16, destPort: uint16, interfaceName: string = "") =
  var packet: SynPacket
  var pseudoHdr: PseudoHeader
  var checkBuf: TcpChecksumBuffer

  # 1. Remplissage de l'en-tête IPv4 (20 octets)
  packet.ip.verIhl = 0x45 
  packet.ip.tos = 0
  packet.ip.totLen = htons(cast[uint16](sizeof(SynPacket)))
  packet.ip.id = htons(12345) 
  packet.ip.fragOff = 0
  packet.ip.ttl = 64
  packet.ip.protocol = 6 # IPPROTO_TCP
  packet.ip.check = 0 
  packet.ip.saddr = ipToUint32(srcIp)
  packet.ip.daddr = ipToUint32(destIp)

  # Calcul du Checksum de l'en-tête IP
  packet.ip.check = computeChecksum(cast[ptr16](addr packet.ip), sizeof(IpHeader))

  # 2. Remplissage de l'en-tête TCP (20 octets)
  packet.tcp.source = htons(srcPort)
  packet.tcp.dest = htons(destPort)
  packet.tcp.seq = htonl(11223344) 
  packet.tcp.ackSeq = 0
  packet.tcp.doffRes = 0x50 
  packet.tcp.flags = 0x02 # Flag SYN
  packet.tcp.window = htons(1024)
  packet.tcp.check = 0
  packet.tcp.urgPtr = 0

  # 3. Préparation du Pseudo-Header pour le checksum TCP
  pseudoHdr.saddr = packet.ip.saddr
  pseudoHdr.daddr = packet.ip.daddr
  pseudoHdr.reserved = 0
  pseudoHdr.protocol = 6
  pseudoHdr.tcpLength = htons(cast[uint16](sizeof(TcpHeader)))

  # 4. Copie dans le buffer contigu et calcul du Checksum TCP
  checkBuf.pseudo = pseudoHdr
  checkBuf.tcp = packet.tcp
  packet.tcp.check = computeChecksum(cast[ptr16](addr checkBuf), sizeof(TcpChecksumBuffer))


  # 5. Aiguillage de l'injection sans pollution visuelle
  when defined(linux):
    if linuxSendPacket(addr packet, sizeof(packet), packet.ip.daddr, destPort):
      echo "[+] SYN packet successfully injected under Linux to " & destIp & ":" & $destPort
    else:
      echo "[-] Injection failed on Linux."
      
  elif defined(windows):
    let targetInterface = if interfaceName != "": interfaceName else: "\\Device\\NPF_Loopback"
    if winSendPacket(targetInterface, addr packet, sizeof(packet)):
      echo "[+] SYN packet successfully injected under Windows via Npcap to " & destIp & ":" & $destPort
    else:
      echo "[-] Npcap injection failed on Windows."