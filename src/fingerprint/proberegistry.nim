# ================================================
# src/fingerprint/proberegistry.nim
# ================================================
#
# Registre global des sondes, rempli par AUTO-ENREGISTREMENT : chaque fichier
# de probes/*.nim s'ajoute lui-même via registerProbe() au moment de son
# import (effet de bord exécuté une seule fois, au chargement du module).
#
# Ce fichier ne connaît AUCUNE sonde en particulier — volontairement, pour
# casser le cycle d'imports : les fichiers de probes/ ont besoin d'importer
# registerProbe() d'ici, et registry.nim a besoin d'importer les fichiers de
# probes/ pour déclencher leur enregistrement. Si ce module-ci importait lui
# aussi les probes, on aurait un import circulaire. En le gardant "vide",
# la dépendance ne va que dans un sens : probes/*.nim -> proberegistry.nim.

import types

var probeRegistry: seq[ServiceProbe] = @[]

proc registerProbe*(probe: ServiceProbe) =
    ## Appelée une fois par fichier de sonde, au niveau module (pas dans un
    ## proc), pour s'ajouter automatiquement au registre dès l'import.
    probeRegistry.add(probe)

proc getAllProbes*(): seq[ServiceProbe] =
    probeRegistry
