## =======================================================
## src/syn/win_pcap.nim
## 
## Gestion exclusive de Npcap / wpcap.dll (Windows)
## =======================================================

when not defined(windows):
  {.error: "This module can only be compiled on Windows."}

type
  PcapHandle* = ptr object # Handle opaque pour la session pcap

  # Cartographie de la structure C pcap_if_t pour lister les interfaces
  PcapIfT* {.packed.} = object
    next*: ptr PcapIfT
    name*: cstring
    description*: cstring
    addresses*: pointer
    flags*: uint32


# Déclaration des fonctions de la DLL
proc pcap_findalldevs(alldevs: ptr (ptr PcapIfT), errbuf: cstring): cint 
  {.importc: "pcap_findalldevs", dynlib: "wpcap.dll", cdecl.}

proc pcap_freealldevs(alldevs: ptr PcapIfT) 
  {.importc: "pcap_freealldevs", dynlib: "wpcap.dll", cdecl.}

proc pcap_open_live(device: cstring, snaplen: cint, promisc: cint, to_ms: cint, errbuf: cstring): PcapHandle 
  {.importc: "pcap_open_live", dynlib: "wpcap.dll", cdecl.}
  
proc pcap_sendpacket(p: PcapHandle, buf: ptr uint8, size: cint): cint 
  {.importc: "pcap_sendpacket", dynlib: "wpcap.dll", cdecl.}
  
proc pcap_close(p: PcapHandle) 
  {.importc: "pcap_close", dynlib: "wpcap.dll", cdecl.}


# --- Fonctions de Haut Niveau Exposées à l'outil ---

# Récupère proprement la liste des interfaces Windows disponibles
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


# Gère l'ouverture et l'envoi du paquet brut
proc winSendPacket*(interfaceName: string, packetPtr: pointer, size: int): bool =
  var errbuf = newString(256)
  let handle = pcap_open_live(interfaceName.cstring, 65535, 1, 1000, errbuf.cstring)
  
  if handle == nil:
    echo "[-] Error pcap_open_live: ", errbuf
    return false

  let sendResult = pcap_sendpacket(handle, cast[ptr uint8](packetPtr), cast[cint](size))
  pcap_close(handle)
  return sendResult == 0