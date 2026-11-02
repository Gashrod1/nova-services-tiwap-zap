# TP — DAST avec OWASP ZAP sur TIWAP

> Dans ce dépôt, `TIWAP/` désigne la racine du dépôt ; `reports-ci/` contient les rapports téléchargés depuis l'artefact du run GitHub Actions.

NOVA SERVICES — Application cible : TIWAP (commit `1f9d2ac`), exécutée dans un
laboratoire isolé. Scan : *Baseline Scan* ZAP (exploration + analyse passive,
aucun test d'attaque actif).

## Environnement

| Élément | Valeur |
|---|---|
| Application | TIWAP, Flask 1.x / Werkzeug 2.0.3 / Python 3.6.15, service `app` |
| Base | MongoDB 4.4, service `db`, **non publiée** sur l'hôte |
| Scanner | `ghcr.io/zaproxy/zaproxy:stable` — ZAP **2.17.0**, service `zap` |
| Cible du scan | `https://app:5000` (nom de service, réseau Compose) |
| Interface navigateur | `https://127.0.0.1:5000` uniquement |
| CI | GitHub Actions, dépôt **privé** `Gashrod1/nova-services-tiwap-zap`, run `38880746878` |

### Prérequis (partie 4) — versions des outils (clients, relevées le 02/11/2026)

```
$ docker --version          → Docker version 29.9.0, build f415da838b
$ docker compose version    → Docker Compose version 5.6.0
$ git --version             → git version 2.56.0
```

### Écarts par rapport à l'énoncé (constatés, pas supposés)

1. **TIWAP écoute en HTTPS, pas en HTTP.** `app.py:913` lance
   `app.run(..., debug=True, ssl_context=context)` avec le certificat
   auto-signé de `certificate/`. Une requête `http://app:5000` reçoit
   `Connection reset by peer` : le premier run CI a échoué pour cette raison.
   La cible correcte est `https://app:5000` (ZAP accepte les certificats
   auto-signés ; `curl` a besoin de `-k`).
2. **Chemins de rapport.** Avec ZAP 2.17, `-r` et `-J` sont relatifs à
   `/zap/wrk`. La commande de l'énoncé (`-r /zap/wrk/zap-report.html`) produit
   `NoSuchFileException /zap/wrk/zap/wrk/zap-report.html` : le scan tourne,
   mais aucun rapport n'est écrit. Commande corrigée :

```bash
docker compose exec zap zap-baseline.py \
  -t https://app:5000 -m 2 \
  -r zap-report.html -J zap-report.json
```

## Partie 1 — Déploiement

Fichier Compose modifié : `TIWAP/docker-compose.yml`
(port app limité à `127.0.0.1:5000:5000`, section `ports` de `db` supprimée,
service `zap` ajouté, attribut obsolète `version` retiré).

**Q1 — Pourquoi démarrer et vérifier l'application avant ZAP ?**
Le DAST n'analyse que ce que l'application *répond*. Si elle n'est pas prête,
ZAP explore une page d'erreur ou une connexion refusée et produit un rapport
vide ou trompeur, qui ressemble à « aucune alerte ». Notre premier run CI
l'illustre : sans vérification préalable, une cible mal adressée (HTTP au lieu
de HTTPS) aurait donné un scan « réussi » sans rien analyser. La vérification
(`curl` en boucle dans le workflow) transforme ce cas en échec explicite.

**Q2 — Pourquoi ne pas exposer MongoDB à l'hôte ?**
Seule l'application a besoin de la base, et elle la joint par le nom `db` sur
le réseau Compose. Publier `27017` (sur `0.0.0.0` dans le fichier d'origine)
rendrait la base joignable depuis le réseau local avec des identifiants
triviaux (`username` / `password`) inscrits dans le dépôt. Cela agrandit la
surface d'attaque sans aucun bénéfice pour le TP. C'est le principe du moindre
privilège appliqué au réseau.

### Vérifications locales (16/10/2026)

```
$ ss -ltn | grep -E ':5000|:27017'
LISTEN 0 4096 127.0.0.1:5000 0.0.0.0:*        # 27017 absent : MongoDB non publié

$ curl -skI https://127.0.0.1:5000/
HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Server: Werkzeug/2.0.3 Python/3.6.15          # ni CSP, ni X-Frame-Options, ni X-Content-Type-Options

$ curl -sk -X POST https://127.0.0.1:5000/login -d 'username=ZAP&password=x'
500 — TypeError: 'NoneType' object is not subscriptable // Werkzeug Debugger
     ... SELECT username, password FROM users WHERE username = ?", (username,))

$ curl -sk -X POST https://127.0.0.1:5000/login -d 'username=admin&password=admin'
302 -> /dashboard
```

## Partie 3 — Résultat du scan

Rapports : `reports-ci/zap-report.html` et `reports-ci/zap-report.json`
(artefact `zap-reports` du run GitHub Actions).

```
FAIL-NEW: 0  WARN-NEW: 15  INFO: 0  IGNORE: 0  PASS: 52
```

*Résumé console relevé à l'écran, log non conservé.* Le nombre « WARN-NEW: 15 »
est recoupé par les JSON, qui contiennent 15 règles distinctes (`pluginid`).
En revanche, ni « PASS: 52 » ni le code de sortie ne figurent dans les
rapports : ces deux valeurs ne sont donc pas vérifiables a posteriori.

Le scan local (`TIWAP/reports/`, 16/10/2026 11:55) donne les **mêmes règles**
que le run CI (les mêmes 15 `pluginid`, avec les mêmes niveaux de risque et de
confiance), mais pas un résultat strictement identique. Le JSON CI contient
**18** entrées d'alerte, contre **17** en local. L'entrée 10049
« Non-Storable Content » (Info) n'apparaît que dans le run CI. Ce léger écart
vient de l'exploration, qui varie d'un scan à l'autre. D'après la documentation
de `zap-baseline.py`, le code de sortie vaut 2 quand des WARN sont présents
(1 = FAIL, 0 = rien). C'est pour cela que le workflow utilise `-I`.

| ID | Alerte | Risque (confiance) | URL principale |
|---|---|---|---|
| 10202 | Absence of Anti-CSRF Tokens | Moyen (Faible) | `GET /` — `<form method="post" action="/login">` |
| 10038 | Content Security Policy Header Not Set | Moyen (Haute) | `/`, 5 réponses |
| 10020 | Missing Anti-clickjacking Header | Moyen (Moyenne) | `/` |
| 10099 | Source Code Disclosure - SQL | Moyen (Moyenne) | `POST /login` — `SELECT username, password FROM users WHERE username` |
| 90022 | Application Error Disclosure | Faible (Moyenne) | `POST /login` — `HTTP/1.0 500 INTERNAL SERVER ERROR` |
| 90004 | Cross-Origin-Embedder/Opener/Resource-Policy manquants | Faible (Moyenne) | `/`, `/index.css` |
| 10063 | Permissions Policy Header Not Set | Faible (Moyenne) | 5 réponses |
| 10036 | Server Leaks Version Information | Faible (Haute) | `Server: Werkzeug/2.0.3 Python/3.6.15` |
| 10035 | Strict-Transport-Security Header Not Set | Faible (Haute) | 5 réponses HTTPS |
| 10021 | X-Content-Type-Options Header Missing | Faible (Moyenne) | 4 réponses |
| 10111, 10027, 10109, 10049, 10015 | Informatives (formulaire d'authentification, commentaires suspects, appli « moderne », cache) | Info | — |

### 8.1 — Relevé détaillé des alertes (description et recommandation ZAP)

Les descriptions et recommandations sont celles du rapport JSON CI (champs
`desc` et `solution`), résumées en français. La colonne « Vérification
manuelle » indique si l'observation suffit ou si l'impact doit être confirmé
dans son contexte.

| ID | Alerte (risque / confiance) | Preuve relevée par ZAP | Description ZAP (résumé) | Recommandation ZAP (résumé) | Vérification manuelle |
|---|---|---|---|---|---|
| 10202 | Absence of Anti-CSRF Tokens — Moyen / **Faible** | Formulaire `<form method="post" action="/login">` sur `GET /` | Aucun jeton anti-CSRF dans un formulaire HTML. Un site tiers peut faire envoyer une requête par le navigateur de la victime, à son insu. | Utiliser un framework ou une bibliothèque anti-CSRF éprouvée (ex. OWASP CSRFGuard), éliminer les XSS qui contourneraient la protection, exiger un jeton imprévisible par requête. | **Oui** : la confiance est faible. Vérifier la présence d'un jeton et l'attribut `SameSite` du cookie, puis l'impact selon le formulaire (login ou formulaire authentifié). |
| 10038 | CSP Header Not Set — Moyen / Haute | En-tête `Content-Security-Policy` absent sur 5 réponses | La CSP est une couche supplémentaire contre les XSS et les injections de contenu : elle déclare les sources de contenu autorisées. | Configurer le serveur web, le serveur d'application ou le répartiteur de charge pour envoyer `Content-Security-Policy`. | Non pour l'observation (absence certaine). Oui pour la gravité métier (défense en profondeur). |
| 10020 | Missing Anti-clickjacking Header — Moyen / Moyenne | Ni `X-Frame-Options`, ni CSP `frame-ancestors` sur `/` | La réponse n'empêche pas l'intégration de la page dans un cadre (clickjacking). | Envoyer `X-Frame-Options: DENY` (ou `SAMEORIGIN`), ou une CSP avec `frame-ancestors`, sur toutes les pages. | Non pour l'observation. Oui pour l'impact (pages sensibles exposées en iframe ?). |
| 10099 | Source Code Disclosure - SQL — Moyen / Moyenne | `POST /login` : `SELECT username, password FROM users WHERE username` | Le serveur a divulgué du code source de l'application (motif SQL). | Ne pas rendre le code source accessible, que ce soit par une extension alternative ou dans un fichier servi par le serveur. | **Oui** : la vérification a montré une trace Werkzeug (mode debug), pas une injection SQL (voir la Partie 4). |
| 90022 | Application Error Disclosure — Faible / Moyenne | `POST /login` : `HTTP/1.0 500 INTERNAL SERVER ERROR` | La page contient un message d'erreur qui peut révéler des informations sensibles (chemins de fichiers, exceptions). C'est un faux positif possible s'il s'agit d'une page de documentation. | Relire le code de la page, mettre en place des pages d'erreur personnalisées, renvoyer au client un identifiant d'erreur et garder le détail dans les journaux serveur. | **Oui** : confirmé, et plus grave que le niveau indiqué (débogueur Werkzeug `__debugger__`). |
| 90004 | Cross-Origin-Embedder/Opener/Resource-Policy manquants — Faible / Moyenne | `/` et `/index.css` (COEP 1, COOP 1, CORP 4) | Ces en-têtes isolent le contexte de navigation et les ressources des autres origines (fuites entre origines, attaques de type Spectre). | Envoyer `Cross-Origin-Embedder-Policy: require-corp`, `Cross-Origin-Opener-Policy: same-origin` et `Cross-Origin-Resource-Policy: same-origin`. | Non pour l'observation. L'impact est faible, à arbitrer selon les ressources tierces utilisées (CDN). |
| 10063 | Permissions Policy Header Not Set — Faible / Moyenne | Absent sur 5 réponses | Cet en-tête restreint les fonctions du navigateur (caméra, géolocalisation…) accessibles aux ressources de la page. | Configurer le serveur pour envoyer `Permissions-Policy`. | Non. Durcissement. |
| 10036 | Server Leaks Version Information — Faible / Haute | `Server: Werkzeug/2.0.3 Python/3.6.15` | L'en-tête `Server` révèle la version du serveur, ce qui aide à trouver des vulnérabilités connues. | Supprimer l'en-tête `Server` ou le rendre générique (serveur, proxy, répartiteur). | Oui, pour le contexte : révèle un serveur de développement et un Python en fin de vie. |
| 10035 | Strict-Transport-Security Header Not Set — Faible / Haute | Absent sur 5 réponses HTTPS | HSTS (RFC 6797) impose aux navigateurs de n'utiliser que HTTPS pour ce site. | Configurer le serveur ou le répartiteur pour envoyer `Strict-Transport-Security`. | Oui, pour la pertinence : sans objet en laboratoire (certificat auto-signé), exigé en production. |
| 10021 | X-Content-Type-Options Header Missing — Faible / Moyenne | Absent sur 4 réponses | Sans `nosniff`, certains navigateurs devinent le type MIME et peuvent interpréter une réponse comme un autre type de contenu. | Envoyer `X-Content-Type-Options: nosniff` sur toutes les pages, avec un `Content-Type` correct. | Non. Durcissement. |
| 10111, 10027, 10109, 10049, 10015 | Informatives | Formulaire d'authentification, commentaires suspects, appli « moderne », cache | Constats de contexte, pas des défauts en soi. | — | 10109 sert à expliquer la faible couverture de l'exploration. |

**Injection SQL : non détectée par le scan.** Aucune alerte 40018 (SQL
Injection) n'apparaît, et c'est attendu : cette règle est *active*, le Baseline
Scan ne l'exécute pas. De plus, les modules vulnérables
(`vulnerabilities/SQLi.py`) sont derrière l'authentification, que ZAP n'a pas
franchie (scan non authentifié, alerte 10109 : « No links have been found »,
exploration très limitée).

## Partie 4 — Qualification

### Tableau de qualification

| Alerte constatée | Risque ZAP | Vérification effectuée | Qualification | Action |
|---|---|---|---|---|
| **10099 Source Code Disclosure - SQL** + **90022 Application Error Disclosure** (`POST /login`, 500) | Moyen + Faible | Lecture du code : ZAP a envoyé `username=ZAP`. `db_manager.py:42` teste `type(result) != 'NoneType'` (toujours vrai), puis `data[1]` sur `None` → `TypeError` → 500. Comme `debug=True` (`app.py:913`), Werkzeug renvoie la **trace complète avec le code source** et charge son **débogueur interactif** (`/login?__debugger__=yes&cmd=resource&f=debugger.js` vu par ZAP). | **Vulnérabilité confirmée**, plus grave que ne l'indique ZAP : divulgation de code + console de débogage Werkzeug exposée (exécution de code Python à distance si le PIN est obtenu ; le PIN est écrit dans les journaux du conteneur). Ce n'est **pas** une injection SQL : la requête affichée est paramétrée (`?`). | Corriger : `debug=False`, pages d'erreur génériques, corriger le test `None`. |
| **10202 Absence of Anti-CSRF Tokens** (`/` → formulaire `/login`) | Moyen (confiance faible) | Formulaire POST sans jeton ; après connexion, `Set-Cookie: session=...; HttpOnly; Path=/` : ni `SameSite`, ni `Secure` (vérifié avec curl). | Constat **confirmé techniquement** ; impact limité sur un formulaire de connexion (login CSRF), plus fort sur les formulaires authentifiés non explorés. | Corriger : Flask-WTF `CSRFProtect`, `SESSION_COOKIE_SAMESITE=Lax`. |
| **10038 CSP Header Not Set** (+ 10020, 10021, 90004, 10063) | Moyen / Faible | `curl -kI https://127.0.0.1:5000/` : aucun en-tête `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`. | Observation **certaine** (absence d'en-tête), mais c'est un **défaut de durcissement**, pas une faille en soi : la CSP limite l'impact d'une XSS, elle ne la crée pas. Devient important car TIWAP contient des XSS. | Corriger au reverse proxy ou via `@app.after_request`. |
| **10036 Server Leaks Version Information** | Faible (Haute) | `Server: Werkzeug/2.0.3 Python/3.6.15` | Confirmé. Révèle un **serveur de développement** et un Python **en fin de vie** (3.6, EOL 2021). Le vrai risque est l'obsolescence, pas l'en-tête. | Servir via Gunicorn derrière un reverse proxy ; mettre à jour Python. |
| **10035 HSTS Not Set** | Faible (Haute) | Réponses HTTPS sans `Strict-Transport-Security`. | Confirmé, mais **sans objet en laboratoire** (certificat auto-signé, pas de nom de domaine). Pertinent pour une appli NOVA exposée. | Justifier en labo ; exiger en production (au reverse proxy). |

### Pourquoi une alerte doit être vérifiée (analyse)

L'alerte **10099 « Source Code Disclosure - SQL »** montre les deux pièges :

- **Le libellé induit en erreur.** On pourrait y lire « ZAP a trouvé une
  injection SQL ». En réalité ZAP a seulement reconnu un motif SQL dans une
  page d'erreur. La requête affichée est paramétrée : sur ce chemin, il n'y a
  pas d'injection. L'injection réelle de TIWAP (confirmée au TP SonarQube,
  `vulnerabilities/SQLi.py:22`) n'apparaît **pas** dans ce rapport.
- **La gravité est sous-estimée.** Remonter à la cause (`debug=True`) révèle
  un débogueur Werkzeug actif, soit un risque d'exécution de code, alors que
  ZAP classe la page d'erreur en risque *Faible*.

Un scanner fournit une **observation** (une réponse HTTP contient X). La
**vulnérabilité** est une conclusion : il faut l'URL, la réponse, le code et le
contexte d'exposition. Le niveau ZAP ne devient pas une priorité métier sans
cette analyse.

### Exemple 8.3 — en-tête CSP manquant

- **Réponse concernée :** `GET https://app:5000/` (200) et 4 autres, y compris
  des 404.
- **Utilisateurs non fiables ?** En labo, non (127.0.0.1). Pour une
  application NOVA client exposée sur Internet, oui.
- **Risque :** sans CSP, une XSS injectée peut charger et exécuter n'importe
  quel script, ou exfiltrer des données vers un domaine tiers. La CSP est une
  défense en profondeur.
- **Où corriger :** dans l'application (`after_request`, ou Flask-Talisman) ou
  au reverse proxy (nginx `add_header Content-Security-Policy ... always;`).
  Le proxy couvre toutes les applications d'un coup ; l'application connaît
  mieux ses besoins (CDN jsdelivr pour Bootstrap, scripts inline).
- **Vérification :** relancer le baseline : la règle 10038 doit passer de
  WARN-NEW à PASS. Contrôle rapide :
  `curl -kI https://127.0.0.1:5000/ | grep -i content-security`.

### Lien avec l'injection SQL étudiée avec SonarQube

| | SonarQube (SAST) | ZAP Baseline (DAST) |
|---|---|---|
| Injection SQL `SQLi.py` | Non signalée (règle S3649 absente de l'édition Community) | Non signalée (règle active, zone authentifiée non explorée) |
| `debug=True` / débogueur | Détectable par règle (configuration Flask) | **Observé en fonctionnement** (trace + `__debugger__`) |
| En-têtes, cookies, version serveur | Hors de portée (dépend du déploiement) | Détectés |

Les deux outils ont manqué l'injection SQL, pour des raisons différentes. Il
faut donc soit un **scan actif authentifié** (ZAP Full Scan avec contexte de
connexion), soit une approche IAST, soit une revue manuelle avec rejeu
contrôlé, comme au TP précédent.

## Partie 5 — Fiches de traitement NOVA SERVICES

Date de référence : 16/10/2026.

| Champ | Fiche 1 | Fiche 2 | Fiche 3 |
|---|---|---|---|
| **Référence** | ZAP-90022 / 10099 — DAST-2026-001 | ZAP-10202 — DAST-2026-002 | ZAP-10038 (+10020, 10021, 90004, 10063, 10035) — DAST-2026-003 |
| **Application** | TIWAP (cible de laboratoire) | TIWAP | TIWAP |
| **Actif métier analogue** | Portail client NOVA (gestion des prestations), Flask exposé sur Internet | Formulaires du portail client (modification de coordonnées, validation de prestations) | Toutes les applications web NOVA exposées |
| **Impact** | C/I/D élevés : divulgation de code et de structure SQL ; console Werkzeug → exécution de code sur le serveur, accès aux données clients | Intégrité : un site tiers fait réaliser des actions à un client connecté | Défense en profondeur : aggrave l'impact d'une XSS (vol de session) et du clickjacking |
| **Priorité** | **Critique** — exploitable sans authentification, impact serveur complet, correction triviale | **Élevée** sur les formulaires authentifiés, moyenne sur le login | **Moyenne** — pas exploitable seul, mais l'application contient des XSS connues |
| **Responsable** | Équipe de développement (code) + exploitation (configuration de déploiement) | Équipe de développement | Exploitation (reverse proxy) + sécurité (définition de la politique CSP) |
| **Échéance** | 17/10/2026 (J+1) | 30/10/2026 (J+14) | 15/11/2026 (J+30) |
| **Action** | `debug=False` piloté par variable d'environnement ; Gunicorn au lieu du serveur de dev ; gestionnaire d'erreur 500 générique ; corriger `if data is None` | `CSRFProtect` (Flask-WTF) ; `SESSION_COOKIE_SAMESITE="Lax"`, `SESSION_COOKIE_SECURE=True` | Bloc d'en-têtes commun au reverse proxy : CSP (d'abord en `Report-Only`), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, HSTS en production |
| **Vérification** | `POST /login` avec utilisateur inconnu → page « Invalid Credentials », pas de 500 ni de `__debugger__` ; nouveau baseline : 90022 et 10099 en PASS | Revue de code + test : POST sans jeton → 400 ; nouveau baseline : 10202 en PASS | `curl -kI` + nouveau baseline : 10038, 10020, 10021 en PASS |
| **Statut** | Ouvert | Ouvert | Ouvert (10035 HSTS : **accepté** en labo, à exiger en production) |

## Partie 6 — Intégration CI (GitHub Actions)

Fichier : `TIWAP/.github/workflows/dast.yml`. Déclencheurs : push sur
`master`/`main`, pull request, lancement manuel.

Étapes :
1. `docker compose up -d --build` (le runner `ubuntu-latest` fournit Docker,
   pas besoin de Docker-in-Docker) ;
2. attente active : `curl -k https://app:5000/` depuis le conteneur `zap`,
   36 × 5 s, et échec explicite avec les journaux de l'application en cas de
   délai dépassé ;
3. `zap-baseline.py -t https://app:5000 -m 2 -I -r ... -J ...` (`-I` : les
   WARN n'échouent pas le job ; pour bloquer, retirer `-I` et classer les
   règles en FAIL via un fichier `-c`) ;
4. `upload-artifact` des rapports avec `if: always()`, puis
   `docker compose down -v`.

Historique des runs (preuve d'itération) :

| Run | Résultat | Cause |
|---|---|---|
| 38879488180 | Échec à « Attendre TIWAP » | Cible HTTP alors que l'appli est en HTTPS |
| 38880321764 | Succès, mais artefact sans rapport | Chemin `-r /zap/wrk/...` doublé |
| **38880746878** | **Succès**, `zap-report.html` (112 Ko) + `.json` (44 Ko) | — |

**Limite :** l'artefact est un fichier brut. Pour un affichage dans l'onglet
*Security* de GitHub, il faudrait un rapport SARIF (template ZAP
`sarif-json`) envoyé avec `github/codeql-action/upload-sarif`, ce qui demande
GitHub Advanced Security sur un dépôt privé.

## Partie 7 — Mini-tableau de bord

| Indicateur | Définition / calcul | Source | Fréquence | Responsable | Décision permise | Valeur au 16/10/2026 (TIWAP) |
|---|---|---|---|---|---|---|
| **Vulnérabilités confirmées ouvertes, par priorité** | Nb de fiches au statut Ouvert ou En cours, par priorité métier (pas par risque ZAP) | Registre des fiches / tickets | Hebdomadaire | RSSI / équipe sécurité | Réallouer des développeurs, décaler une mise en production | Critique 1 · Élevée 1 · Moyenne 1 |
| **Vulnérabilités prioritaires hors délai** | Nb de fiches Critique/Élevée dont l'échéance est dépassée | Registre (échéance vs date du jour) | Quotidienne | Responsable de l'équipe dev | Escalade à la direction, accepter formellement le risque ou bloquer | 0 |
| **Délai médian de correction (MTTR)** | Médiane (date de vérification − date de détection) des fiches corrigées, par priorité | Registre + date du scan de vérification | Mensuelle | Équipe sécurité | Revoir les SLA, le processus de correction | N/A (aucune correction encore) |
| **% de corrections vérifiées par un nouveau scan** | Fiches « Corrigé » avec scan de vérification où la règle passe en PASS ÷ total des fiches « Corrigé » | Rapports JSON ZAP comparés (`pluginid` par URL) | À chaque pipeline | Équipe sécurité | Refuser la clôture d'un ticket déclaré corrigé sans preuve | N/A |
| **Couverture DAST des applications critiques** | Applications critiques avec au moins un scan DAST réussi sur 30 jours ÷ applications critiques recensées | Inventaire des actifs (TP1) + historique CI | Mensuelle | RSSI | Prioriser l'intégration du DAST aux applications non couvertes | 1/1 en labo |
| **Taux d'échec technique des scans** | Runs DAST en échec hors alertes (cible injoignable, rapport absent) ÷ runs | Historique GitHub Actions | Hebdomadaire | Exploitation / DevOps | Fiabiliser le pipeline : un scan muet n'est pas un scan propre | 2/3 (67 %) pendant la mise au point |

Le nombre brut d'alertes (15 WARN ici) n'est pas un indicateur de sécurité. Il
compte surtout des en-têtes manquants. Il augmenterait si on authentifiait le
scan, alors que l'application ne deviendrait pas moins sûre : la couverture
serait simplement meilleure.

## Questions de compréhension

1. **SAST vs DAST.** Le SAST lit le code sans l'exécuter : il trouve des
   chemins de code dangereux, tôt, avec leur localisation, mais ne voit ni la
   configuration de déploiement ni le comportement réel. Le DAST interroge
   l'application en fonctionnement, en boîte noire : il voit les en-têtes, les
   cookies, les erreurs réelles et la configuration, mais pas le code, et
   seulement les pages qu'il a atteintes.
2. **Pourquoi une application en fonctionnement ?** Le DAST analyse des
   réponses HTTP. Sans application qui répond, il n'y a rien à observer.
   Exemple : le débogueur Werkzeug n'existe qu'à l'exécution.
3. **Pourquoi `https://app:5000` ?** Dans le conteneur ZAP, `localhost` est ZAP
   lui-même. Le DNS de Compose résout le nom de service `app`. Le port 5000 est
   celui du conteneur, pas celui publié sur l'hôte. Et c'est `https` parce que
   TIWAP active TLS.
4. **Passif vs actif.** Le passif observe le trafic issu de l'exploration, sans
   charge malveillante. L'actif envoie des charges d'attaque (injections,
   XSS…), peut modifier des données ou perturber le service, et demande une
   autorisation et un environnement dédié.
5. **Pourquoi le Baseline ne garantit pas une SQLi ?** Une injection SQL se
   révèle en injectant des charges et en comparant les réponses : c'est la
   règle active 40018, non exécutée par le Baseline. Ici, en plus, les pages
   vulnérables sont derrière l'authentification. Résultat : aucune alerte SQLi,
   alors que la faille existe.
6. **Alerte vs vulnérabilité confirmée.** Une alerte est une observation
   automatique, avec un niveau de confiance. Une vulnérabilité confirmée a été
   vérifiée (code, rejeu, contexte) et a un impact démontré. Exemple : 10099
   ressemble à une fuite SQL, mais c'est en réalité un débogueur exposé.
7. **Prioriser sur une application critique.** On combine la criticité des
   données et du service, l'exposition (Internet ou interne, authentification
   ou non), la facilité d'exploitation, les mesures compensatoires (WAF,
   proxy) et le coût de correction. Sur une application critique exposée, une
   faille exploitable sans authentification devient Critique même si ZAP dit
   « Faible ».
8. **Pourquoi conserver les rapports en CI ?** Pour la traçabilité (preuve
   qu'un contrôle a eu lieu sur un commit donné), la comparaison entre deux
   scans (régressions, vérification des corrections), l'audit, et pour
   alimenter les indicateurs à partir du JSON, sans committer de rapports dans
   le dépôt.
9. **Éviter de publier une application vulnérable.** Ports liés à
   `127.0.0.1`, base non publiée, dépôt privé, pas de déploiement automatique
   (le workflow ne fait que scanner un environnement éphémère détruit par
   `down -v`), pas de secrets ni de données réelles, réseau de labo isolé.
10. **Indicateurs d'efficacité du processus.** MTTR par priorité, vulnérabilités
    hors délai, % de corrections vérifiées par un nouveau scan, taux de
    réouverture (régressions), couverture des applications critiques.

## Conclusion — limites du DAST et complémentarité avec le SAST

Le scan de référence a produit 15 alertes, surtout des en-têtes de durcissement
manquants. Sa découverte la plus utile n'était pas évidente à la lecture : une
« fuite de code SQL » à risque Moyen qui, une fois qualifiée, révèle un
débogueur Werkzeug exposé, la vulnérabilité la plus grave du rapport. À
l'inverse, l'injection SQL connue de TIWAP n'a été trouvée **ni par SonarQube
Community, ni par le Baseline ZAP**.

Limites constatées du DAST :
- couverture limitée aux pages atteintes : sans authentification, presque tout
  TIWAP reste invisible ;
- le mode passif ne détecte pas les failles d'injection ;
- les niveaux de risque sont génériques et ignorent le contexte métier ;
- la configuration de l'outil est fragile : deux erreurs silencieuses (mauvais
  protocole, chemin de rapport) auraient pu passer pour un « scan propre ».

Le SAST et le DAST couvrent des angles différents : le SAST voit le code, le
DAST voit le déploiement. Aucun n'est une garantie. NOVA SERVICES doit les
combiner (et ajouter un scan actif authentifié en recette, puis une revue
manuelle des alertes importantes), et piloter à partir de vulnérabilités
**qualifiées et vérifiées après correction**, pas à partir de compteurs
d'alertes.

## Nettoyage du laboratoire (section 14)

Depuis la racine du dépôt `TIWAP/` :

```bash
docker compose down     # arrête et supprime les conteneurs app, db et zap
docker compose ps       # doit afficher une liste vide
```

**À exécuter et confirmer par l'utilisateur.** Ce compte rendu n'apporte pas
la preuve que ces commandes ont été lancées après le scan local de 11:55. À la
rédaction, aucun port 5000 ou 27017 n'était en écoute sur l'hôte, mais l'état
des conteneurs n'a pas été vérifié. Les rapports utiles sont conservés dans
`TIWAP/reports/` et `reports-ci/`. Le volume MongoDB est conservé : pas de `-v`,
pour ne pas supprimer de données sans vérification. La CI, elle, fait
`docker compose down -v` sur son environnement éphémère.

## Livrables (section 12)

| # | Livrable demandé | Emplacement / statut |
|---|---|---|
| L1 | Fichier Compose modifié | `TIWAP/docker-compose.yml` (Partie 1) |
| L2 | Capture prouvant que TIWAP fonctionne localement | **Capture à fournir par l'utilisateur** : navigateur sur `https://127.0.0.1:5000` (après acceptation du certificat auto-signé), page d'accueil ou de connexion TIWAP visible, barre d'adresse lisible. Si possible, ajouter dans la même capture ou une seconde la sortie de `docker compose ps` (services `app`, `db` et `zap` *Up*, port `127.0.0.1:5000->5000`). |
| L3 | Rapport HTML et JSON de ZAP | `reports-ci/zap-report.html` et `.json` (run CI 38880746878) ; `TIWAP/reports/zap-report.html` et `.json` (scan local) |
| L4 | Tableau de qualification (au moins 3 alertes réelles) | Partie 4, « Tableau de qualification » (5 lignes), avec le relevé détaillé 8.1 (Partie 3) |
| L5 | Analyse expliquant pourquoi une alerte doit être vérifiée | Partie 4, « Pourquoi une alerte doit être vérifiée » (alerte 10099) |
| L6 | Fiche de traitement contextualisée NOVA SERVICES | Partie 5 (3 fiches) |
| L7 | Fichier `.gitlab-ci.yml` | **Remplacé par `TIWAP/.github/workflows/dast.yml` (GitHub Actions, job `dast_zap`).** L'introduction de l'énoncé laisse le choix : « automatiser le contrôle dans GitLab CI ou Github action ». Le dépôt est hébergé sur GitHub, et le modèle de la section 10.2 est vide dans le PDF fourni. Le workflow reprend les étapes de la section 10 : démarrer les services, attendre que TIWAP réponde, lancer le baseline, publier les rapports en artefacts. Voir la Partie 6. |
| L8 | Capture du pipeline et de ses artefacts | ✅ [`captures/L8-run-github-actions.png`](captures/L8-run-github-actions.png) : run **38880746878** (https://github.com/Gashrod1/nova-services-tiwap-zap/actions/runs/38880746878) en succès, avec l'artefact `zap-reports` (30,4 Ko). |
| L9 | Mini-tableau de bord (au moins 4 indicateurs) | Partie 7 (6 indicateurs) |
| L10 | Conclusion : limites du DAST, complémentarité SAST | Section « Conclusion » |
