## =======================================================
## src/syn/checksum.nim
## =======================================================


proc computeChecksum*(data: ptr uint16, length: int): uint16 =
    var
        sum: uint32 = 0
        nleft = length
        ptrData = data
    
    # Addition des mots de  16 bits
    while nleft > 1:
        sum += ptrData[]
        ptrData = cast[ptr16](cast[uintptr](ptrData) + 2)
        nleft -= 2

    # Si la longueur est impaire, on ajoute le dernier octet restant
    if nleft == 1:
        sum += cast[ptr uint8](ptrData)[]

    # On réinjecte les bits de retenue de poids fort (carry) dans les 16 bits de poids faible
    sum = (sum shr 16) + (sum and 0xFFFF)
    sum += (sum shr 16)

    # Complément à un (inversion de tous les bits)
    result = not cast[uint16](sum)