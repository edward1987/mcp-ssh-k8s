# Verificare de securitate — 2026-11-01

**Aplicatia are suport de deployment Docker/Kubernetes/Linux si corectii de securitate testate. Imaginea finala scanata are 0 CRITICAL si 0 HIGH; raman 25 de constatari MEDIUM si 9 LOW in pachete de baza.** Nu exista exceptii sau CVE-uri ascunse in workflow. Rezultatele scannerului nu reprezinta o garantie de securitate sau validarea infrastructurii de productie.

Au fost revizuite sursele aplicatiei si interfetei, identitatile/OAuth/MFA, izolarea vaulturilor si partajarilor, aprobarile si politicile SSH/kubectl, procesele copil, persistenta, TLS, importurile, configuratia de deployment si buildurile. Modificarile existente in directorul de lucru au fost pastrate. Verificarea este o analiza de cod si testare automata, nu un pentest independent sau o garantie ca toate vulnerabilitatile posibile au fost eliminate.

## Probleme corectate

| Zona | Constatare | Corectie si verificare |
| --- | --- | --- |
| Kubeconfig | `exec` si `auth-provider` permiteau pornirea de programe pe server, inclusiv din vaulturi ale membrilor | Respinse la import **si inainte de fiecare executie**, inclusiv pentru date vechi si partajate; teste negative pentru comenzi locale |
| Kubeconfig | Referinte suplimentare la fisiere, TLS dezactivat si proxy-uri puteau expune credentiale | Sunt acceptate configuratii incluse integral, cu HTTPS si verificare TLS; sunt respinse ambele forme `tokenFile`/`token-file` si `proxy-url` |
| Kubectl | URL-urile manifest si listele separate prin virgula puteau citi fisiere locale sau accesa servicii interne | `-f` accepta exclusiv stdin `-` cu parametrul `manifest`; fisierele/template-urile locale si override-urile de identitate raman interzise |
| Flaguri kubectl | Combinatii precum `-Ashttps://...` puteau ascunde schimbarea serverului, iar flagurile cu underscore erau normalizate diferit de kubectl | Gruparea flagurilor scurte este respinsa; se pastreaza valorile atasate pentru optiunile care le consuma integral; numele lungi sunt normalizate inainte de verificare; teste pentru override-uri, fisiere si watch/follow |
| Procese copil | Kubectl mostenea mediul procesului si preferintele utilizatorului gazda | Mediu minimal, home/cache/temp proprii fiecarei operatii, kuberc dezactivat, fara variabile secrete mostenite; timeout cu terminare fortata |
| SSH read-only | Prefixe ca `ip addr`, `hostname`, `date`, `ss` si `journalctl` acceptau si operatii care modifica sistemul | Verificare a argumentelor, inclusiv prescurtari iproute2, flaguri citate si optiuni scurte grupate; teste pentru modificarile de adresa/ruta, ceas/nume, inchidere conexiuni si stergere/rotire loguri |
| Aprobari | Politica sau destinatia putea fi schimbata cat timp o cerere astepta aprobare | Configuratia resursei se reverifica dupa asteptare; o modificare cere o cerere noua; teste SSH si Kubernetes |
| Gateway | Era nevoie de acces pentru servere fara a expune direct listenerul administrativ | Gateway optional, HTTPS canonic obligatoriu pentru server, Host/Origin stricte, bootstrap blocat inclusiv cu majuscule, codificari sau normalizare de cale; headerele proxy furnizate de client sunt eliminate |
| Origini/CSRF | Compararea doar a hostului permitea o origine cu schema diferita; compararea unor tokenuri UTF-8 putea arunca exceptie | Se compara originea completa; compararea CSRF foloseste lungimea in octeti |
| Consent OAuth/CSP | `form-action 'self'` bloca in Chromium redirectul POST catre callback-ul clientului, pe alta origine | Doar pagina autentificata a unei cereri active permite originea callback-ului curent; teste browser pentru aprobare/refuz pe ambele listenere, PKCE, expirare, CSRF si izolarea exceptiei CSP |
| MCP discovery si navigare | Vaultul blocat respingea initialize/tools-list cu HTTP 503, iar linkul spre vault ramanea pe portul MCP fara interfata | Discovery autentificat returneaza doar definitii statice; toate toolurile pastreaza blocarea pe vault si controlul resurselor. Navigarea foloseste portul administrativ configurat/originea HTTPS; auditul retine metodele discovery, fara credentiale |
| Resurse de autentificare | Mai multe operatii scrypt simultane pot epuiza memoria unui container | Maximum doua derivari active si opt in asteptare, refuz pentru suprasarcina sau parametri KDF neacceptati; test de concurenta |
| Audit | Fisier creat cu permisiuni implicite, fara redactare a credentialelor inline si citire integrala a istoricului | `0600` pe Linux, umask `0077`, redactare best-effort, citire a unui sufix limitat; eliminarea afirmatiilor incorecte despre imuabilitate/tamper-evidence |
| SSH timeout | Inchiderea politicoasa nu reprezenta un termen ferm pentru un peer care nu raspunde | Conexiunea este distrusa la timeout; inchiderea prematura respinge operatia; test cu un canal care nu se termina |
| Runtime | Documentatia cerea Node 20, desi autentificarea foloseste `node:sqlite` | Node 24 LTS actualizat, engines explicite, CI si installer Windows actualizate la 24.22.2 cu SHA256 verificat |
| Container/Kubernetes | Lipseau buildurile si limitarile de runtime | Runtime distroless fara shell/npm, baze fixate prin digest, UID 1000, rootfs read-only, tmpfs, capabilities eliminate, seccomp, limite de resurse, PVC, probe, ServiceAccount token nemontat si NetworkPolicy restrictiva |

## Vulnerabilitati kubectl identificate si remediate

Scanarea initiala cu **Trivy 0.76.1**, baza de vulnerabilitati actualizata la data verificarii, a gasit doua constatari HIGH in binarul oficial kubectl v1.37.2 descarcat de pe dl.k8s.io:

| Componenta inclusa | Versiune detectata | Constatare HIGH | Versiune de dependenta corectata |
| --- | --- | --- | --- |
| kubectl v1.37.2: `golang.org/x/net` | v0.57.0 | CVE-2026-78669 — consum excesiv de CPU in HTTP/2 | v0.60.0 |
| kubectl v1.37.2: `golang.org/x/text` | v0.40.0 | CVE-2026-56851 — panic in profilul Nickname/precis | v0.41.0 |

Imaginea finala foloseste kubectl v1.37.2 din [buildul Chainguard](https://images.chainguard.dev/directory/image/kubectl/overview), fixat prin digest `sha256:668d137910c3e949ac9ef48accd14063ee22bfe702141487d199e1bc9cfe39b7`. Binarul a fost verificat prin executie si inspectarea metadatelor Go: Go 1.27.3, `golang.org/x/net v0.62.0`, `golang.org/x/text v0.43.0`. Ambele dependente depasesc versiunile corectate, iar scanarea imaginii rezultate nu mai raporteaza aceste CVE-uri. Nu s-au folosit ignore-uri sau clasificari false positive. Schimbarea este o dependenta de furnizor externa, fixata explicit si care trebuie revizuita/rescanata la actualizare.

Referinte primare: [Go HTTP/2 — GO-2026-6611](https://pkg.go.dev/vuln/GO-2026-6611), [Go text — GO-2026-6629](https://pkg.go.dev/vuln/GO-2026-6629).

Prima imagine bazata pe Debian slim includea si numeroase pachete OS/npm raportate HIGH. Aceste pachete au fost eliminate din runtime prin trecerea la distroless. Scanarea imaginii finale nu raporteaza HIGH/CRITICAL in pachetele OS, dependentele Node ale aplicatiei sau kubectl. Pentru `unzip` si `libbz2` copiate separat in runtime, imaginea include si metadatele de pachet necesare scannerului.

## Constatari MEDIUM/LOW ramase

Scanarea completa a imaginii finale raporteaza **25 MEDIUM si 9 LOW**, nu zero vulnerabilitati de toate severitatile. Sunt constatari pentru `libc6`, familia GCC (`gcc-14-base`, `libgcc-s1`, `libgomp1`, `libstdc++6`), `libbz2-1.0`, `zlib1g` si `unzip`. Unele CVE-uri apar pentru mai multe pachete: numerele de mai sus sunt constatari pachet/CVE, nu numarul de CVE-uri distincte.

Scannerul nu indica o versiune corectata disponibila pentru aceste pachete in distributia imaginii. Nu am demonstrat exploatabilitatea fiecarei constatari si nu le-am eliminat din raport. Inventarul exact, cu ID-uri, versiuni si severitati, se afla in [rezultatul scanarii](security/container-findings-2026-11-01.json). Urmareste actualizarile imaginilor/pachetelor si rescaneaza inainte de livrare. Workflow-ul opreste HIGH/CRITICAL; MEDIUM/LOW necesita evaluare conform politicii de risc a mediului in care se instaleaza.

## Verificari si limite

- Build TypeScript si teste pentru criptare/persistenta, OAuth/PKCE/MFA, revocare, izolarea conturilor, partajari, importuri, politici, aprobari si gateway. Regresiile discovery verifica vaulturi legacy/personale blocate, blocarea tuturor toolurilor, continuarea dupa deblocare si respingerea tokenurilor revocate.
- Teste browser pentru autentificare, consent OAuth urmat de initialize/tools-list cu vault blocat, navigarea dintre porturi, CSP/XSS, CSRF, roluri, migrare, auto-lock si interfata; date sintetice, fara folosirea vaultului real.
- Rezultatul curent: **90 de teste trecute pe Windows si Linux**, **17 teste browser trecute**, build TypeScript si testul imaginii Docker trecute.
- `npm audit`: zero vulnerabilitati raportate la verificare. Acesta nu acopera pachetele OS, Node livrat separat sau executabilele externe.
- Test container real: Linux, UID non-root, filesystem read-only, porturi interne pe loopback, autentificare, Host/Origin, blocare bootstrap extern, health, kubectl, date private, persistenta dupa restart si SIGTERM.
- Manifeste aplicate intr-un cluster kind izolat: Pod Security `restricted`, pod Ready, PVC legat, Service/Ingress/NetworkPolicy acceptate, apel API real prin modulul kubectl al aplicatiei cu credentiale temporare si stergerea kubeconfigului, apoi pastrarea cheii identity dupa inlocuirea podului. Testul adauga in NetworkPolicy doar destinatia API-ului temporar. Clusterul de test nu contine controller Traefik; TLS-ul de ingress si combinatia CNI/NetworkPolicy trebuie verificate in mediul final.
- Scanarea surselor pentru secrete si configuratii nu a raportat secrete sau erori HIGH/CRITICAL in sursele si configuratiile verificate. Datele locale, cache-urile, artefactele si `node_modules` au fost excluse; nu a fost scanat istoricul Git pentru secrete sterse anterior.
- Unitatea systemd este furnizata pentru instalare Linux; nu a fost activata ca serviciu pe masina utilizatorului. Node, proxy-ul, certificatul, DNS, registry-ul, storage-ul si destinatiile autorizate sunt configurate in mediul de deployment.
- Nu s-a facut deployment pe infrastructura utilizatorului si nu au fost executate comenzi pe hosturile SSH sau clusterele reale stocate in vault.

Comenzile repetabile sunt in `DEPLOYMENT.md` si `.github/workflows/security.yml`. `npm run test:k8s` creeaza si sterge doar un cluster temporar, cu kubeconfig separat. Rezultatele sunt valabile pentru continutul si versiunile verificate; actualizarile cer repetarea scanarilor.

## Limite ale modelului de securitate

`read-only` reduce modificarile directe, dar nu este o bariera de confidentialitate: `cat`, logurile, inspectiile Docker si API-urile Kubernetes pot dezvalui date accesibile identitatii de pe tinta. Foloseste conturi SSH si RBAC cu privilegii minime; allowlisturile personalizate si modul `free` sunt decizii de incredere ale proprietarului. Nu oferi unui agent o identitate root/cluster-admin fara a accepta consecintele.

SSH foloseste TOFU: prima cheie vazuta trebuie obtinuta printr-o cale de incredere. Blocarea vaultului sau revocarea accesului impiedica actiunile urmatoare, dar nu anuleaza o comanda deja trimisa la o tinta. Rezultatele unei operatii autorizate pot contine secrete; nu sunt salvate integral in audit, dar ajung la clientul autorizat.

Criptarea vaulturilor nu protejeaza impotriva administratorului sistemului de operare, citirii memoriei procesului, furtului intregului director identity sau unui runtime compromis. Cheia identity si SQLite trebuie protejate impreuna; backupurile necesita protectie separata. Credentialele partajate trebuie sa ramana utilizabile de serviciu conform modelului de partajare, inclusiv cand vaultul proprietarului este blocat.

Nu presupune ca redactarea auditului detecteaza orice secret scris arbitrar intr-o comanda. Jurnalul este modificabil de utilizatorul serviciului/administratorul gazdei; pentru retentie obligatorie si detectarea modificarilor, foloseste un colector extern cu protectie proprie. Logurile necesita politica de rotire/retentie si monitorizarea spatiului pe volumul persistent.

Gateway-ul nu acorda incredere identitatii sau IP-ului din headere `Forwarded`/`X-Forwarded-*`. Limitarile interne sunt partajate pentru conexiunile proxy-ului; adauga rate limiting per client la marginea HTTPS. Izoleaza reteaua backend si restrictioneaza iesirile: configurarea tintelor SSH/API reprezinta in mod intentionat acces de retea din procesul serverului.
# Actualizare container — 2026-11-05

Distribuția Docker și Kubernetes folosește acum același target implicit semnat Ed25519. Buildul nesemnat necesită explicit `runtime-dev`. Workflow-ul `release-container.yml` publică în GHCR numai imaginea care a trecut testele Docker, kind și scanarea HIGH/CRITICAL și produce atestare de proveniență, SBOM și bundle cu digestul și cheia publică fixate. Cheia reală de release și protecțiile mediului GitHub nu au fost configurate în timpul implementării; imaginea locală a fost semnată exclusiv cu o cheie efemeră de test.

Validare locală pe Linux amd64: 133 teste trecute atât pe Windows, cât și în targetul Docker `test`; build TypeScript reușit; Compose și workflow-urile trec validarea. Testele de container verifică semnătura, lipsa cheii private/secrets mount la runtime, refuzul scrierii în cod, autentificarea, persistența datelor, extractorul de arhive și închiderea SIGTERM. O copie bind-mounted a unui fișier public a fost alterată controlat: procesul a ieșit cu 78, iar restaurarea fișierului și restartul nu au eliminat incidentul persistent.

Clusterul kind temporar a verificat imaginea semnată, podul non-root/read-only, PVC, apel kubectl real către clusterul temporar cu eliminarea kubeconfigului, persistența identității după înlocuirea podului și refuzul pornirii cu 78 după un incident păstrat pe PVC. Clusterul și volumele de test au fost eliminate. Aceste teste nu certifică terminarea TLS sau aplicarea NetworkPolicy într-un anumit CNI/ingress de producție.

Scanarea inițială a raportat HIGH `CVE-2026-76844` în biblioteca de sistem `zlib1g` a bazei distroless. Verificarea dependențelor dinamice a confirmat că Node și unzip nu folosesc acea bibliotecă; Node include propria implementare zlib. Biblioteca partajată neutilizată, fișierele sale de documentație și înregistrările pachetului au fost eliminate efectiv din filesystem. Nu există suprimare a CVE-ului sau editare a versiunii pentru mascarea rezultatului. Rescanarea imaginii finale a returnat 0 HIGH și 0 CRITICAL; rezumatul cu ID-ul imaginii este în [container-findings-2026-11-05.json](security/container-findings-2026-11-05.json). Raportul din 2026-11-01 de mai jos rămâne istoric.

Referință pentru remedierea upstream a problemei gzwrite: [commitul zlib](https://github.com/madler/zlib/commit/df84af25dc1942490e1d1c899a07619152a46148). Publicarea și instalarea sunt descrise în [CONTAINER_RELEASE.md](CONTAINER_RELEASE.md).

