# Package

version       = "0.1.0"
author        = "n40y"
description   = "Nim ports scanner"
license       = "MIT"
srcDir        = "src"
bin           = @["VoightNim"]


# Dependencies

requires "nim >= 2.2.10"
requires "docopt"
requires "regex"

# Modules principaux
import VoightNim
import cli
import prober
import topports

# Moteur de fingerprinting
import fingerprint/engine
import fingerprint/matcher
import fingerprint/types
import fingerprint/services
import fingerprint/registry
import fingerprint/osCatalog
import fingerprint/utils

# Sondes
import probes/ftp
import probes/http
import probes/redis
import probes/smtp
import probes/ssh


# Signatures
import signatures/http/init
import signatures/ssh/init
import signatures/ftp/init
import signatures/redis/init
import signatures/smtp/init
import signatures/os/init

import signatures/kerberos/init
import signatures/ldap/init
import signatures/smb/init
