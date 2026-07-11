import re2
import types

proc getFtpProbe*(): ServiceProbe =
  result = ServiceProbe(
    name: "FTP",

    payload: "USER anonymous\r\n",

    ports: @[21],

    timeoutMs: 1000,

    rarity: 1,

    ssl: false
  )

  result.matches.add MatchRule(
    pattern: re2"FileZilla Server",

    product: "FileZilla",

    vendor: "FileZilla",

    family: "FTP",

    cpe: "cpe:/a:filezilla:filezilla_server",

    confidence: 100
  )

  result.matches.add MatchRule(
    pattern: re2"Microsoft FTP Service",

    product: "Microsoft FTP",

    vendor: "Microsoft",

    family: "FTP",

    cpe: "cpe:/a:microsoft:ftp_service",

    confidence: 100
  )
