##=================================================
## src/fingerprint/utils.nim
## 
## Fichier contenant les utilitaires
##================================================

import std/strutils


proc sanitizeDisplay*(raw: string): string =
  result = newStringOfCap(raw.len)

  for c in raw:
    let code = ord(c)
    if code >= 32 and code <= 126:
      result.add(c)
    elif c in {'\r', '\n', '\t'}:
      result.add(' ')
    else:
      result.add('.')

proc toHexPreview*(raw: string, maxBytes: int = 16): string =
  var bytes: seq[string] = @[]
  let limit = min(raw.len, maxBytes)
  
  for i in 0 .. limit:
    bytes.add(toHex(ord(raw[i]), 2))
  
  result = bytes.join(" ")
  if raw.len > maxBytes:
    result.add("...")

proc isPrintable*(s: string): bool =
  if s.len == 0:
    return false

  var printableCount = 0
  for c in s:
    if ord(c) >= 32 and ord(c) <= 126:
      inc printableCount
  
  return (printableCount / s.len) > 0.6


proc toBytes*(s: string): seq[byte] =
  result = newSeq[byte](s.len)
  for i, c in s:
    result[i] = byte(c)


proc toString*(b: seq[byte]): string =
  result = newString(b.len)
  for i, c in b:
    result[i] = char(c)


proc startsWithIgnoreCase*(s, prefix: string): bool =
  s.toLowerAscii.startsWith(prefix.toLowerAscii)


proc containsIgnoreCase*(s, needle: string): bool =
  s.toLowerAscii.contains(needle.toLowerAscii)


proc splitHttpHeaders*(banner: string): tuple[headers: string, body: string] =
  let idx = banner.find("\r\n\r\n")
  if idx >= 0:
    result.headers = banner[0 ..< idx]
    result.body = banner[(idx + 4) .. ^1]
  else:
    result.headers = banner
    result.body = ""


# === FIX UTF-8 ===
proc toSafeString*(s: string): string =
  ## Convertit une chaîne binaire brute en UTF-8 valide.
  ## En code les octets > 127 sur 2 octets (codepoints 128..255).
  ## Évite les crashs de la lib regex tout en préservant les signatures binaires.
  result = ""
  for c in s:
    let val = c.uint8
    
    if val < 128:
      result.add(char(val))
    else:
      let b1 = char(0xC0 or (val div 64))
      let b2 = char(0x80 or (val and 0x3F))
      result.add(b1)
      result.add(b2)