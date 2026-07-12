# src/fingerprint/utils.nim

import std/strutils

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
  ## Sépare une réponse HTTP brute en (en-têtes, corps) sur le séparateur
  ## CRLF CRLF. Si le séparateur est absent (banner tronqué, ou pas du HTTP),
  ## tout est considéré comme des en-têtes et le corps est vide.
  let idx = banner.find("\r\n\r\n")

  if idx >= 0:
    result.headers = banner[0 ..< idx]
    result.body = banner[(idx + 4) .. ^1]
  else:
    result.headers = banner
    result.body = ""