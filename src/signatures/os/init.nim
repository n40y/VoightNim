## =============================================================================
## signatures/os/init.nim
##
## Point d'entrée unique pour les signatures OS. Même convention que
## signatures/http/init.nim : un fichier par famille d'OS, agrégés ici.
## =============================================================================

import ../../fingerprint/types
import ./linux
import ./windows

proc getOsSignatures*(): seq[OsMatchRule] =
  result = @[]

  result.add getLinuxOsSignatures()
  result.add getWindowsOsSignatures()