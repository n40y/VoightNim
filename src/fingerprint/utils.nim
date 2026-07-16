##=================================================
##
## src/fingerprint/utils.nim
##
##================================================

import std/strutils
import std/unicode


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