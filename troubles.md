# Problèmes identifiés suites aux tests du 14/07/26:

## Bug 1 — le vrai coupable du "no banner received" sur 88/389/445

Dans prober.nim, grabBanner boucle sur tous les probes (allProbes, dans l'ordre HTTP → SSH → Redis → FTP → SMTP → Kerberos → LDAP → SMB) et les essaie un par un sur la même connexion, sans jamais regarder probe.ports :

### Résultat concret sur le port 88 :

tu ouvres la connexion vers le KDC, et avant que ta sonde Kerberos ait la moindre chance de parler, tu lui envoies déjà GET / HTTP/1.1... (sonde HTTP), puis rien (SSH), puis INFO\r\n (Redis), puis rien (FTP), puis EHLO scanner.local\r\n (SMTP) — tout ça sur la même socket. Un KDC Kerberos interprète les 4 premiers octets reçus comme une longueur de trame TCP (RFC 4120) ; en recevant GET  (0x47455420), il croit qu'un message de ~1,2 Go arrive et attend indéfiniment la suite. La sonde Kerberos, tentée en dernier (ou avant-dernier), parle dans le vide — connexion déjà désynchronisée. Même mécanisme pour LDAP (389) et SMB (445), essayées encore plus tard dans la liste : c'est presque garanti qu'elles n'aient plus de connexion exploitable au moment où c'est leur tour. Le port 80 marche, lui, uniquement parce que HTTP est premier dans getAllProbes().

### Le champ ports:

seq[uint16] existe déjà sur ServiceProbe — il n'est juste jamais utilisé pour filtrer. Le fix : sélectionner la (les) sonde(s) dont ports contient le port scanné, et une connexion neuve par sonde essayée plutôt qu'une connexion recyclée :

## Bug 2 — l'épuisement de descripteurs sur les gros ranges

Dans scanPortAsync, quand le connect() timeout côté application (withTimeout renvoie false), le socket n'est pas fermé — volontairement, pour éviter un risque de réutilisation de descripteur pendant que le connect() OS est encore en vol :

C'est ça, le vrai problème. Sur un port fermé, le RST arrive vite et le socket se ferme immédiatement (branche else). Mais sur un port filtré/silencieux (pas de RST, paquet juste ignoré), le connect() OS peut mettre plusieurs dizaines de secondes à abandonner de lui-même — bien plus long que ton timeoutMs applicatif (800ms). Le descripteur reste donc ouvert et comptabilisé pendant tout ce temps, alors que scanRange a déjà enchaîné sur le chunk suivant.

Sur 1-1000 (peu de chunks, scan court), ça n'a pas le temps de s'accumuler. Sur 1000-65535 (~130 à 320 chunks), chaque chunk qui laisse fuir ne serait-ce que quelques descripteurs finit, chunk après chunk, par dépasser ulimit -n — d'où le crash à la même profondeur de scan, indépendamment de -s 200 ou -s 500 (tu l'as bien remarqué en testant les deux).

La bonne nouvelle : la crainte du commentaire ("réutilisation du descripteur") ne s'applique pas ici. asyncnet.close() désenregistre le fd du sélecteur epoll avant de le fermer réellement ; même si l'OS recycle ensuite ce numéro de fd pour un nouveau socket, l'event loop ne peut plus jamais le rattacher à l'ancien Future puisqu'il n'est plus dans sa table. Fermer immédiatement, comme dans les deux autres branches, est donc safe :

## Un point à garder en tête pour la suite, une fois ces deux bugs corrigés et le banner effectivement reçu sur 88/389/445 :

* LDAP : ça devrait bien marcher tel quel — les OID Microsoft (1.2.840.113556...) et OpenLDAProotDSE apparaissent en ASCII brut dans la réponse BER, donc tes regex actuelles vont matcher directement sans décodage.

* Kerberos : ça matchera parfois (le texte d'erreur du KDC contient souvent littéralement "Kerberos"), mais c'est un heuristique fragile — un KDC Windows AD répond en général avec un texte d'erreur très laconique, sans "Microsoft"/"Active Directory" dedans.

* SMB : ici il y a un vrai souci de fond à anticiper — une réponse SMB2 Negotiate n'a aucune chaîne de texte ("Windows", "Samba"...) dans sa structure binaire (c'était vrai en SMB1, plus en SMB2/3). Le signal exploitable, c'est le dialecte négocié (2 octets) et les OID SPNEGO du security buffer, pas du texte à regexer. Tes patterns actuels ne matcheront quasiment jamais contre une vraie réponse.

## C'est pour ça que:

* Le port 80 marche. Parce que HTTP est la première sonde dans getAllProbes().