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
