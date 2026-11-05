# Integritatea release-ului și oprirea la incident

Checksumurile sunt generate la build, după compilare și instalarea dependențelor finale. Pornirea aplicației doar le verifică. Nu reconstruiește manifestul și nu acceptă automat fișierele existente pe disc drept sursă de încredere.

## Semnarea în CI

Release-ul Windows necesită secretul GitHub Actions `MCP_SSH_INTEGRITY_SIGNING_KEY`: o cheie privată Ed25519, în format PEM PKCS8, generată și păstrată de operator într-un mediu de încredere. Cheia privată nu intră în Git sau în installer. Workflow-ul transmite secretul numai pasului de release; scriptul îl elimină din mediul proceselor de test și semnează numai payloadul final.

Jobul folosește mediul GitHub `release`. Operatorul trebuie să configureze protecțiile acelui mediu (review și restricții pe branch/tag) și secretul de semnare acolo. Declararea mediului în YAML nu activează singură aceste protecții. Nu expuneți cheia de semnare buildurilor pentru PR-uri nevalidate.

Rezultatele sunt `integrity.json` (checksumuri SHA-256), `integrity.sig` (semnătura Ed25519) și `integrity.pub` (cheia publică SPKI DER în base64). Verificatorul folosește cheia publică **fixată în configurația de deployment**, prin `MCP_SSH_INTEGRITY_PUBLIC_KEY`, nu o cheie aleasă de manifest. În Windows, installerul fixează cheia publică distribuită în configurația serviciului și a launcherului. Distribuția inițială a installerului și a cheii publice trebuie verificată independent. Installerul nu are încă semnătură Authenticode.

Pe Linux, fixați cheia publică într-un fișier de mediu administrat de root, în afara directorului aplicației, și activați `MCP_SSH_REQUIRE_SIGNED_INTEGRITY=1`. Schimbarea checksumurilor, falsificarea semnăturii sau eliminarea semnăturii nu permit pornirea cu cheia publică fixată.

Pentru containerul de release, transmiteți cheia privată ca secret BuildKit `integrity_key` și cheia publică de încredere ca build argument `INTEGRITY_PUBLIC_KEY`, sau folosiți `scripts/build-container.mjs`. Buildul semnează după prune și verifică semnătura cu cheia publică furnizată. Cheia privată nu este copiată în imagine sau într-un layer. Imaginea fixează numai cheia publică în configurația sa, iar deploymentul o fixează din nou independent prin Compose/ConfigMap. Targetul implicit Docker refuză lipsa semnăturii; numai targetul explicit `runtime-dev` permite checksumuri nesemnate. `npm run build` local rămâne un build de dezvoltare nesemnat. Distribuția este descrisă în [CONTAINER_RELEASE.md](CONTAINER_RELEASE.md).

Nu a fost generată sau configurată o cheie privată reală de release în această modificare. Până la configurarea secretului de către operator, buildul installerului refuză distribuirea unui release nesemnat.

## Detectarea în timpul rulării

Notificările `fs.watch` urmăresc fișierele protejate. Un eveniment de scriere/înlocuire/ștergere declanșează incidentul chiar dacă fișierul este restaurat rapid la conținutul original. O verificare completă la fiecare 5 secunde completează notificările; există și verificări pe traseele de acces. Erorile mecanismului de monitorizare sunt tratate ca incidente. Cache-urile de dezvoltare, datele vaulturilor și logurile nu sunt fișiere de program protejate de acest manifest.

La detecție, aplicația scrie un mesaj critic și încearcă să salveze `<director-date>/integrity-incident.json`, să oprească procesele kubectl active, să curețe fișierele temporare de credențiale și să blocheze vaulturile. Procesul se termină cu codul **78**, fără `abort()` sau core dump intenționat. Cleanup-ul este best effort; comenzile deja trimise serverelor externe nu pot fi anulate retroactiv.

La pornire, orice incident persistent sau verificare eșuată produce ieșire 78 înainte de importul aplicației. Nu se deschide niciun listener HTTP și nu se afișează formulare de parole. Launcherul Windows anunță incidentul într-un mesaj local. Un restart automat nu elimină incidentul; unitatea systemd nu repornește automat la codul 78. Alți supervisori pot încerca să repornească procesul, dar aplicația refuză fiecare pornire cât timp markerul există.

## Recuperare

Opriți serviciul/supervisorul. Păstrați logurile și markerul pentru investigație. Reinstalați dintr-un release verificat, confirmați independent cheia publică și integritatea sistemului, apoi arhivați și eliminați manual **numai** fișierul `integrity-incident.json` din directorul de date. Porniți din nou serviciul. Nu există resetare a incidentului prin API, deblocare cu parolă sau regenerare automată a checksumurilor.

## Limitele protecției

Detectarea prin notificări nu garantează timp real: sistemul de operare poate pierde evenimente, iar un event loop blocat poate întârzia verificarea periodică. Nu publicăm o garanție că fiecare modificare este detectată instantaneu.

Semnătura previne falsificarea manifestului față de o cheie publică de încredere. Nu împiedică un atacator cu control complet asupra verificatorului/runtime-ului să elimine verificarea sau să modifice numai memoria. Protejați codul și configurația serviciului prin permisiuni OS, imagini fixate prin digest și, unde este disponibil, code signing/politici de execuție verificate independent. Un crash nu retrage secretele deja exfiltrate.
