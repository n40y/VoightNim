# src/fingerprint/registry.nim
#
# Point d'entrée unique qui charge toutes les sondes. Chaque import ci-dessous
# déclenche l'auto-enregistrement de la sonde correspondante dans
# proberegistry.nim (voir la ligne `registerProbe(...)` en bas de chaque
# fichier probes/*.nim). Ajouter une nouvelle sonde = une seule ligne ici.

import proberegistry
export proberegistry    # ré-expose getAllProbes() : VoightNim.nim n'a rien à changer

# Ces imports ne servent qu'à déclencher l'auto-enregistrement de chaque
# sonde (effet de bord au chargement du module) : le compilateur les
# signale comme "non utilisés" à tort, on désactive ce warning précis
# juste ici plutôt que globalement.

{.warning[UnusedImport]: off.}
import ../probes/ftp
import ../probes/http
import ../probes/kerberos
import ../probes/ldap
import ../probes/rdp
import ../probes/redis
import ../probes/smb
import ../probes/smtp
import ../probes/ssh
import ../probes/dns
import ../probes/msrpc