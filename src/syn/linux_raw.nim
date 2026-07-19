## =======================================================
## src/syn/linux_raw.nim
## 
## Gestion exclusive des Raw Sockets sous Linux
## =======================================================

when not defined(linux):
    {.error: "This module can only be compiled on Linux.".}
    

import std/posix

# Gère la création de la socket brute et l'injection du paquet sous Linux
proc linuxSendPacket*(packetPtr: pointer, size: int, destIpBin: uint32, desport: uint16): bool =
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