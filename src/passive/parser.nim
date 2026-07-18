## =================================================
## src/passive/parser.nim
## =================================================

import std/strutils


# Extrait un nom d'hôte au format DNS (Valide pour LLMNR sur port 5355 et mDNS sur port 5353)
proc parseDnsFormat*(payload: string): string =
  if payload.len < 12: 
    return ""

  var idx = 12
  var resultParts: seq[string] = @[]

  while idx < payload.len:
    let length = int(payload[idx].byte)
    if length == 0:
      break
    
    idx.inc
    if idx + length > payload.len:
      return "" 
    
    var part = ""
    for i in 0 ..< length:
      part.add(payload[idx + i])
    
    resultParts.add(part)
    idx.inc(length)

  return resultParts.join(".")


# Décode le format de nom compressé propre à NetBIOS (Ex: LLLFACC...)
proc decodeNetbiosName(encoded: string): string =
  if encoded.len != 32: return ""
  result = ""
  for i in countup(0, 31, 2):
    let c1 = int(encoded[i].byte) - int('A'.byte)
    let c2 = int(encoded[i+1].byte) - int('A'.byte)
    if c1 < 0 or c1 > 15 or c2 < 0 or c2 > 15: 
      return ""
    let decodedChar = chr((c1 shl 4) or c2)
    result.add(decodedChar)
  return result.strip()


# Extrait le nom d'hôte d'une requête NetBIOS Name Service (Port 137)
proc parseNetbiosQuery*(payload: string): string =
  if payload.len < 45: # Header(12) + Length(1) + EncodedName(32)
    return ""
  
  let nameLen = int(payload[12].byte)
  if nameLen != 32: 
    return ""
  
  var encodedName = ""
  for i in 0 ..< 32:
    encodedName.add(payload[13 + i])
    
  return decodeNetbiosName(encodedName)