## =======================================================
## src/syn/linux_raw.nim
## 
## Gestion exclusive des Raw Sockets sous Linux
## =======================================================

when not defined(linux):
    {.error: "This module can only be compiled on Linux.".}
    

import std/[posix, times]

# Gère la création de la socket brute et l'injection du paquet sous Linux
proc linuxSendPacket*(packetPtr: pointer, size: int, destIpBin: uint32, destPort: uint16): bool =
    let sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)
    if sock.int == -1:
        echo "[-] Error: Unable to create raw socket. Are you root (sudo) ?"
        return false

    # Conf de la structure d'adresse de destination
    var sin: SockAddr_in
    sin.sin_family = AF_INET.TSaFamily
    sin.sin_port = htons(destPort)
    sin.sin_addr.s_addr = destIpBin

    # Envoi du paquet forged
    let bytesSent = sendto(sock, packetPtr, size, 0, cast[ptr SockAddr](addr sin), cast[SockLen](sizeof(sin)))

    # Fermeture du socket
    discard close(sock)

    return bytesSent >= 0

# --- Réception (Sniffer) ---
# Contrepartie Linux de winSniffResponses (win_pcap.nim) : au lieu de Npcap,
# on ouvre une socket brute en lecture. Sur AF_INET/SOCK_RAW, le noyau livre
# directement l'en-tête IP (pas d'en-tête Ethernet à sauter, contrairement à
# la trame capturée côté Windows).

proc linuxOpenSniffSocket*(): SocketHandle =
    ## Ouvre une socket brute en lecture pour intercepter les réponses TCP.
    result = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)
    if result.int == -1:
        echo "[-] Error: Unable to open raw sniffing socket. Are you root (sudo) ?"
        return

    # Timeout de réception : sans ça, recv() bloque indéfiniment si aucune
    # réponse n'arrive et le thread ne pourrait jamais revérifier sa deadline.
    var tv: Timeval
    tv.tv_sec = posix.Time(0)
    tv.tv_usec = 200_000  # 200 ms
    discard setsockopt(result, SOL_SOCKET, SO_RCVTIMEO, addr tv, SockLen(sizeof(tv)))

proc linuxCloseSniffSocket*(sock: SocketHandle) =
    discard close(sock)

proc linuxSniffResponses*(sock: SocketHandle, targetIpBin: uint32, ourSrcPort: uint16,
                           durationMs: int,
                           callback: proc(port: uint16, isOpen: bool) {.gcsafe.}) {.gcsafe.} =
    ## Écoute pendant `durationMs` et déclenche `callback` pour chaque
    ## SYN-ACK / RST provenant de `targetIpBin` et adressé à `ourSrcPort`.
    var buffer: array[65535, byte]
    let deadline = epochTime() + (durationMs.float / 1000.0)

    while epochTime() < deadline:
        let n = recv(sock, addr buffer[0], buffer.len, 0)
        if n <= 0:
            continue  # timeout (SO_RCVTIMEO) ou paquet ignoré par le noyau : on reboucle

        if buffer[9] != 6'u8:
            continue  # protocole IP != TCP

        var srcIpBin: uint32
        copyMem(addr srcIpBin, addr buffer[12], 4)
        if srcIpBin != targetIpBin:
            continue  # ne vient pas de la cible scannée

        let ipLen = int(buffer[0] and 0x0F) * 4
        let tcpStart = ipLen

        let dstPort = (uint16(buffer[tcpStart + 2]) shl 8) or uint16(buffer[tcpStart + 3])
        if dstPort != ourSrcPort:
            continue  # ne répond pas à notre port source de scan

        let srcPort = (uint16(buffer[tcpStart]) shl 8) or uint16(buffer[tcpStart + 1])
        let flags = buffer[tcpStart + 13]

        if (flags and 0x12'u8) == 0x12'u8:
            callback(srcPort, true)   # SYN-ACK -> port ouvert
        elif (flags and 0x04'u8) == 0x04'u8:
            callback(srcPort, false)  # RST -> port fermé