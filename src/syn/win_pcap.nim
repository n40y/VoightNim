## =======================================================
## src/syn/win_pcap.nim
## 
## Gestion exclusive de Npcap / wpcap.dll (Windows)
## =======================================================

when not defined(windows):
  {.error: "This module can only be compiled on Windows.".}

type
  PcapHandle* = ptr object 

  PcapIfT* {.packed.} = object
    next*: ptr PcapIfT
    name*: cstring
    description*: cstring
    addresses*: pointer # Pointeur vers le premier maillon de PcapAddr
    flags*: uint32

  # --- AJOUT : Structures pour parser les IP des interfaces ---
  PcapAddr {.packed.} = object
    next*: ptr PcapAddr
    `addr`*: pointer       # Pointeur vers un SockAddr
    netmask*: pointer
    broadaddr*: pointer
    dstaddr*: pointer

  WinSockAddrIn {.packed.} = object
    sin_family*: uint16
    sin_port*: uint16
    sin_addr*: uint32    # IP au format binaire (Network Byte Order)
    sin_zero*: array[8, byte]

  PcapPkthdr {.packed.} = object
    ts_sec: clong
    ts_usec: clong
    caplen*: uint32
    len*: uint32

# Déclaration des fonctions de la DLL
proc pcap_findalldevs(alldevs: ptr (ptr PcapIfT), errbuf: cstring): cint 
  {.importc: "pcap_findalldevs", dynlib: "wpcap.dll", cdecl.}

proc pcap_freealldevs(alldevs: ptr PcapIfT) 
  {.importc: "pcap_freealldevs", dynlib: "wpcap.dll", cdecl.}

proc pcap_open_live*(device: cstring, snaplen: cint, promisc: cint, to_ms: cint, errbuf: cstring): PcapHandle 
  {.importc: "pcap_open_live", dynlib: "wpcap.dll", cdecl.}
  
proc pcap_sendpacket*(p: PcapHandle, buf: ptr uint8, size: cint): cint 
  {.importc: "pcap_sendpacket", dynlib: "wpcap.dll", cdecl.}

proc pcap_next_ex(p: PcapHandle, pkt_header: ptr (ptr PcapPkthdr), pkt_data: ptr (ptr uint8)): cint 
  {.importc: "pcap_next_ex", dynlib: "wpcap.dll", cdecl.}
  
proc pcap_close*(p: PcapHandle) 
  {.importc: "pcap_close", dynlib: "wpcap.dll", cdecl.}

# --- Fonctions de Haut Niveau ---

proc listInterfaces*(): seq[tuple[name: string, desc: string]] =
  var 
    alldevs: ptr PcapIfT
    errbuf = newString(256)
  result = @[]
  if pcap_findalldevs(addr alldevs, errbuf.cstring) == 0:
    var it = alldevs
    while it != nil:
      let desc = if it.description != nil: $it.description else: "No description"
      result.add(($it.name, desc))
      it = it.next
    pcap_freealldevs(alldevs)

# --- Trouve le GUID de l'interface associée à une IP locale ---
proc getInterfaceNameByIp*(localIpBin: uint32): string =
  result = ""
  var 
    alldevs: ptr PcapIfT
    errbuf = newString(256)
  if pcap_findalldevs(addr alldevs, errbuf.cstring) == 0:
    var it = alldevs
    while it != nil:
      var addrIt = cast[ptr PcapAddr](it.addresses)
      while addrIt != nil:
        if addrIt.`addr` != nil: # Corrige ici
          let sin = cast[ptr WinSockAddrIn](addrIt.`addr`) # Corrige ici
          if sin.sin_family == 2: # 2 = AF_INET (IPv4)
            if sin.sin_addr == localIpBin:
              result = $it.name
              break
        addrIt = addrIt.next
      if result != "": break
      it = it.next
    pcap_freealldevs(alldevs)

proc winSendPacket*(interfaceName: string, packetPtr: pointer, size: int): bool =
  var errbuf = newString(256)
  let handle = pcap_open_live(interfaceName.cstring, 65535, 1, 100, errbuf.cstring)
  if handle == nil: return false
  let sendResult = pcap_sendpacket(handle, cast[ptr uint8](packetPtr), cast[cint](size))
  pcap_close(handle)
  return sendResult == 0

proc winSniffResponses*(handle: PcapHandle, targetIpBin: uint32, callback: proc(port: uint16, isOpen: bool) {.gcsafe.}) {.gcsafe.} =
  var 
    header: ptr PcapPkthdr
    data: ptr uint8
  
  while pcap_next_ex(handle, addr header, addr data) >= 0:
    if data == nil: continue
    let pkt = cast[ptr array[0..65535, byte]](data)
    
    if pkt[12] == 0x08 and pkt[13] == 0x00:
      let ipStart = 14
      if pkt[ipStart + 9] == 6:
        var srcIp: uint32
        copyMem(addr srcIp, addr pkt[ipStart + 12], 4)
        
        if srcIp == targetIpBin:
          let ipLen = int(pkt[ipStart] and 0x0F) * 4
          let tcpStart = ipStart + ipLen
          
          let srcPort = (cast[uint16](pkt[tcpStart]) shl 8) or cast[uint16](pkt[tcpStart + 1])
          let flags = pkt[tcpStart + 13]
          
          if (flags and 0x12) == 0x12:
            callback(srcPort, true)
          elif (flags and 0x04) == 0x04:
            callback(srcPort, false)