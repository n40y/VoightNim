## =======================================================
## src/syn/prober.nim
## 
## Logique d'assemblage, orchestration Stateless (Sender/Sniffer)
## et routage intelligent automatique.
## =======================================================

import std/[nativesockets, os, strutils, net, random]

import ./types, ./checksum

type
  ScanResponse* = tuple[port: uint16, isOpen: bool]

var chan*: Channel[ScanResponse]

type
  TcpChecksumBuffer {.packed.} = object
    pseudo: PseudoHeader
    tcp: TcpHeader

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

# --- Ruse de la socket UDP éphémère (Furtive & 100% Locale) ---
proc getLocalIpForTarget(targetIp: string): string =
  try:
    var socket = newSocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
    # connect() en UDP applique uniquement les tables de routage de l'OS sans envoyer de paquet
    socket.connect(targetIp, Port(53))
    let (localIp, _) = socket.getLocalAddr()
    socket.close()
    return localIp
  except CatchableError:
    return "127.0.0.1"

when defined(windows):
  import ./win_pcap
elif defined(linux):
  import ./linux_raw

when defined(windows):
  proc windowsSnifferThread(args: tuple[interfaceName: string, targetIpBin: uint32]) {.thread.} =
    var errbuf = newString(256)
    let handle = pcap_open_live(args.interfaceName.cstring, 65535, 1, 500, errbuf.cstring)
    if handle == nil:
      echo "[-] Unable to open the interface for the sniffer."
      return
    
    winSniffResponses(handle, args.targetIpBin) do (port: uint16, isOpen: bool):
      chan.send((port: port, isOpen: isOpen))
      
    pcap_close(handle)

proc sendSynPacket*(srcIp: string, destIp: string, srcPort: uint16, destPort: uint16, interfaceName: string = "") =
  var packet: SynPacket
  var pseudoHdr: PseudoHeader
  var checkBuf: TcpChecksumBuffer

  packet.ip.verIhl = 0x45 
  packet.ip.tos = 0
  packet.ip.totLen = htons(cast[uint16](sizeof(SynPacket)))
  packet.ip.id = htons(12345) 
  packet.ip.fragOff = 0
  packet.ip.ttl = 64
  packet.ip.protocol = 6 
  packet.ip.check = 0 
  packet.ip.saddr = ipToUint32(srcIp)
  packet.ip.daddr = ipToUint32(destIp)

  packet.ip.check = computeChecksum(cast[ptr uint16](addr packet.ip), sizeof(IpHeader))

  packet.tcp.source = htons(srcPort)
  packet.tcp.dest = htons(destPort)
  packet.tcp.seq = htonl(11223344) 
  packet.tcp.ackSeq = 0
  packet.tcp.doffRes = 0x50 
  packet.tcp.flags = 0x02 
  packet.tcp.window = htons(1024)
  packet.tcp.check = 0
  packet.tcp.urgPtr = 0

  pseudoHdr.saddr = packet.ip.saddr
  pseudoHdr.daddr = packet.ip.daddr
  pseudoHdr.reserved = 0
  pseudoHdr.protocol = 6
  pseudoHdr.tcpLength = htons(cast[uint16](sizeof(TcpHeader)))

  checkBuf.pseudo = pseudoHdr
  checkBuf.tcp = packet.tcp
  packet.tcp.check = computeChecksum(cast[ptr uint16](addr checkBuf), sizeof(TcpChecksumBuffer))

  when defined(linux):
    discard linuxSendPacket(addr packet, sizeof(packet), packet.ip.daddr, destPort)
  elif defined(windows):
    discard winSendPacket(interfaceName, addr packet, sizeof(packet))

# --- Orchestrateur SYN Intelligent ---
proc runSynScan*(srcIp: string, targetIp: string, ports: seq[int], interfaceName: string, delayMs: int, jsonMode: bool): seq[int] =
  result = @[]
  let targetBin = ipToUint32(targetIp)
  
  # 1. Détermination intelligente de l'IP source locale
  let computedSrcIp = if srcIp == "" or srcIp == "0.0.0.0": getLocalIpForTarget(targetIp) else: srcIp
  let srcBin = ipToUint32(computedSrcIp)
  
  # 2. Détermination intelligente de l'interface réseau (GUID Windows)
  var computedInterface = interfaceName
  when defined(windows):
    if computedInterface == "":
      computedInterface = getInterfaceNameByIp(srcBin)
      if computedInterface == "":
        computedInterface = "\\Device\\NPF_Loopback" # Fallback securisé

  if not jsonMode:
    echo "[+] Target network resolution successful:"
    echo "    -> Local Source IP : " & computedSrcIp
    when defined(windows):
      echo "    -> Npcap Interface : " & computedInterface

  # 3. Mélange aléatoire (Fisher-Yates) pour la furtivité
  var shuffledPorts = ports
  randomize()
  shuffle(shuffledPorts)
  
  chan.open()
  
  when defined(windows):
    var snifferThread: Thread[tuple[interfaceName: string, targetIpBin: uint32]]
    createThread(snifferThread, windowsSnifferThread, (computedInterface, targetBin))
    if not jsonMode: echo "[+] Npcap sniffer started on secondary thread."
  
  if not jsonMode: echo "[+] Injecting shuffled SYN packets..."
  
  let sourcePort = 44444'u16
  for port in shuffledPorts:
    sendSynPacket(computedSrcIp, targetIp, sourcePort, cast[uint16](port), computedInterface)
    if delayMs > 0:
      sleep(delayMs)
      
  if not jsonMode: echo "[+] Injection complete. Waiting for responses..."
  sleep(1200)
  
  while chan.peek() > 0:
    let (port, isOpen) = chan.recv()
    if isOpen:
      result.add(int(port))
      if not jsonMode:
        echo "[+] PORT " & $port & " : OPEN (SYN-ACK)"
      
  chan.close()
  when defined(windows):
    joinThread(snifferThread)