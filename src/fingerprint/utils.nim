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
  ## Remplace les séquences UTF-8 invalides par �
  result = newStringOfCap(s.len)
  var i = 0
  while i < s.len:
    let runeLen = runeLenAt(s, i)
    if runeLen > 0:
      result.add s[i ..< i + runeLen]
      i += runeLen
    else:
      result.add "�"
      i += 1