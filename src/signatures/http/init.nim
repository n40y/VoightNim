## =============================================================================
## signatures/http/init.nim
##
## Point d'entrée unique pour les signatures HTTP. Agrège toutes les
## catégories (webservers, runtimes, frameworks, monitoring...) en une
## seule liste consommée par probes/http.nim.
##
## Pour ajouter une nouvelle catégorie : créer le fichier dans ce dossier,
## l'importer ci-dessous, et ajouter son proc à la concaténation.
## =============================================================================

import ../../fingerprint/types

import ./webservers
import ./runtimes
import ./frameworks
import ./monitoring

proc getHttpSignatures*(): seq[MatchRule] =
  result = @[]

  result.add getWebServerSignatures()
  result.add getRuntimeSignatures()
  result.add getFrameworkSignatures()
  result.add getMonitoringSignatures()
