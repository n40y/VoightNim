## ===========================================================================
# src/topports.nim
#
# Liste curatée de ports fréquemment utilisés (services standards IANA +
# ports "cloud/dev" courants : bases de données, conteneurs, monitoring...).
#
# IMPORTANT : ceci n'est PAS l'équivalent exact de la "top 1000" de nmap.
# La liste de nmap vient de statistiques réelles de scan à grande échelle
# qu'ils ont collectées ; je n'ai pas ces données précises, donc je ne peux
# pas te la reproduire fidèlement. Si tu veux une vraie parité avec nmap :
#   1. Récupère le fichier `nmap-services` (fourni avec nmap, licence
#      Nmap Public Source License — c'est un fichier de données, pas du code)
#   2. Écris un petit script (Python ou Nim) qui parse ce fichier, trie par
#      la colonne de fréquence, et génère un `seq[int]` Nim à partir des
#      N ports les plus fréquents.
#
## ===========================================================================

const commonPorts* = @[
  21, 22, 23, 25, 53, 67, 68, 69, 80, 88,
  110, 111, 119, 123, 135, 137, 138, 139, 143, 161,
  162, 179, 194, 201, 264, 318, 381, 383, 389, 411,
  412, 443, 444, 445, 464, 465, 497, 500, 512, 513,
  514, 515, 520, 521, 540, 554, 563, 587, 591, 593,
  631, 636, 646, 691, 860, 873, 902, 989, 990, 993,
  995, 1025, 1026, 1027, 1028, 1029, 1080, 1110, 1433, 1434,
  1701, 1720, 1723, 1755, 1900, 2000, 2049, 2121, 2181, 2375,
  2376, 3000, 3128, 3260, 3268, 3269, 3306, 3389, 3690, 3986,
  4000, 4045, 4444, 4567, 4664, 4899, 5000, 5001, 5060, 5061,
  5432, 5555, 5601, 5666, 5672, 5900, 5901, 5984, 5985, 5986,
  6000, 6379, 6443, 6666, 6667, 6881, 7000, 7001, 7077, 7199,
  7443, 7474, 8000, 8008, 8009, 8080, 8081, 8088, 8090, 8091,
  8443, 8500, 8888, 9000, 9042, 9090, 9092, 9100, 9200, 9300,
  9418, 9999, 10000, 10250, 11211, 15672, 20000, 25565, 27017, 27018,
  28017, 32400, 50000, 50070
]