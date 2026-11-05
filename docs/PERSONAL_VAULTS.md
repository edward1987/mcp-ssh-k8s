# Vaulturi personale, VPN și HTTPS real

Instanța de pe server găzduiește vaulturi personale independente. Contul și MFA nu înlocuiesc parola master. Administratorul conturilor nu primește acces la datele personale. Serverul și administratorul sistemului de operare rămân în zona de încredere: credențialele sunt utilizate în memoria procesului pentru conexiunile SSH.

## Inițializare și migrare

1. Oprește vechea instanță și salvează întregul director de date.
2. După login, fiecare utilizator creează un vault cu parolă master separată și salvează cheia de recuperare afișată o singură dată.
3. Pentru vaultul global existent, panoul **Vaultul vechi este disponibil** apare înainte de deblocare și în vaultul personal deblocat. Proprietarul alege **Importă vaultul vechi în contul meu**, introduce parola veche și parola noului vault personal. Dacă a creat deja un vault personal gol, introduce parola sa existentă: cheia de recuperare rămâne valabilă și se salvează backupul acestui vault. Un vault personal care conține resurse nu este suprascris. Migrarea este atribuită explicit unui singur cont; fișierul vechi `vault.json` și backupul său rămân în directorul de date.
4. Granturile globale nu se moștenesc. Proprietarul recreează partajările din **Partajări temporare**.

Vaulturile sunt în `data/vaults/`, cu chei independente și fișiere separate pentru protecția prin parolă și recuperare. Păstrează împreună fișierele `.json` și `.envelope.json`. Pierderea parolei master și a kitului nu poate fi reparată prin resetarea loginului.

Blocarea, expirarea sau revocarea sesiunii unui utilizator nu blochează vaulturile celorlalți. Operațiile AI nu mențin vaultul deschis automat. Cererile noi și cele încă neexecutate sunt refuzate după blocare; comenzile deja lansate pot termina.

## Partajare

Proprietarul alege resursa, destinatarul, aliasul, durata (implicit 24 ore), politica și aprobatorii. O operație limitată este definită ca `Nume|comandă completă`, o linie per operație. Destinatarul invocă ID-ul operației; nu poate modifica șablonul comenzii. Politica resursei originale rămâne obligatorie.

Destinatarul primește referințe, nu cheia SSH, parola ori configurația exportabilă. Resursele partajate se utilizează prin pagina de partajări sau toolurile `list_shared_resources` și `run_shared_operation`. Necesită vaultul destinatarului deblocat. Vaultul proprietarului poate fi blocat: brokerul păstrează o copie criptată, cu o cheie per resursă protejată prin secretul instalării. Modificările salvate de proprietar se propagă automat.

Revocarea, expirarea și dezactivarea contului sunt verificate înainte de execuție și din nou după aprobări. Destinatarul nu poate aproba propria cerere sau redistribui accesul. Aprobatorii au nevoie de login și de propria sesiune de vault. Accesul fără restricții poate dezvălui IP-uri ori alte informații prin rezultatele comenzilor; mascarea câmpurilor conexiunii nu este un mecanism de filtrare a rezultatelor.

## Let’s Encrypt DNS-01 cu Cloudflare

Din **Administrare instanță → HTTPS privat și DNS** (`/identity/admin/tls`), administratorul configurează:

- hostname dintr-un domeniu real aflat în zona Cloudflare;
- IP-ul privat al interfeței serverului, accesibil prin VPN;
- Cloudflare Zone ID și un API token limitat la zona respectivă, cu Zone Read și DNS Edit;
- emailul ACME și mediul staging/producție.

Hostname-ul și IP-ul privat vor exista în DNS public; numele certificatului va apărea în Certificate Transparency. Aceasta nu creează o rută de acces la IP-ul privat. Unele VPN-uri/resolvere blochează răspunsurile DNS publice cu IP privat; administratorul rețelei trebuie să configureze o excepție pentru hostname sau DNS intern corespunzător.

Aplicația creează A/AAAA **DNS-only, fără proxy Cloudflare** și refuză suprascrierea automată a unui DNS conflictual. Pentru validare adaugă TXT sub `_acme-challenge`, așteaptă propagarea și elimină numai recordurile pe care le-a creat. Nu deschide porturile publice 80/443. Sunt necesare conexiuni outbound către API Cloudflare, serviciul ACME și DNS. CAA trebuie să permită Let’s Encrypt.

Începe cu staging pentru verificarea DNS; certificatul staging nu este recunoscut de browsere. Pentru certificatul real debifează staging, salvează și solicită emiterea din nou, acceptând termenii Let’s Encrypt.

La prima configurare repornește aplicația după emitere: metadata OAuth este stabilită la pornire. Adresa de login este preluată automat din configurația HTTPS dacă `AUTH_URL` nu este setată. Un `AUTH_URL` explicit trebuie să coincidă cu originea configurată. Listenerul TLS se leagă numai la IP-ul privat, pe portul 443; contul serviciului trebuie să aibă permisiunea necesară, iar portul să fie liber. Bootstrap-ul rămâne exclusiv pe loopback și este blocat prin gateway.

Cheia certificatului, contul ACME și API tokenul Cloudflare sunt criptate în stocarea operațională protejată de ACL. Reînnoirea este verificată la 12 ore, începând cu 30 zile înainte de expirare; un eșec păstrează certificatul anterior. Certificatul reînnoit se încarcă fără restart când originea nu se schimbă. Interfața indică erorile și necesitatea curățării manuale dacă ștergerea TXT eșuează.

## Tunelul comun și backup

Configurarea, pornirea și oprirea tunelului, instalarea/actualizarea runtime-ului OpenAI și instalarea ajutorului Termius sunt centralizate în **Administrare instanță** (`/identity/admin`). Linkul apare în pagina contului și în interfața vaultului numai pentru administratori, inclusiv când vaultul este blocat. Aceste operații cer o sesiune de cont administrator și CSRF valid, fără deblocarea unui vault personal. Rutele vechi `/api/tunnel/*` și `/api/import/termius-local/setup` nu mai execută operații.

Instalările rulează în fundal, pe rând, cu stare și rezultat în Admin; necesită confirmarea componentei predefinite. Nu se pot trimite comenzi sau nume arbitrare de pachete. Runtime-ul tunelului este verificat SHA-256. Ajutorul Termius este disponibil doar pe Windows și folosește un mediu Python izolat. Într-un container, runtime-ul aplicației se păstrează în directorul de date montat persistent. Importurile care citesc fișierele SSH/Termius de pe server sunt rezervate administratorilor; membrii pot încărca propriul CSV în vaultul personal.

Configurația tunelului aparține instanței și este protejată în `identity/`, separat de vaulturi. Blocarea unui vault personal nu oprește tunelul. VPN-ul este necesar pentru login/deblocare; după autorizare, ChatGPT poate continua prin tunel cât timp sesiunea și vaultul solicitantului sunt valide. Publicarea în workspace nu acordă drepturi la date.

Păstrează tot directorul de date cu aplicația oprită: `identity/` conține cheia instalării și baza operațională, iar `vaults/` conține vaulturile personale. Reinstalarea programului nu trebuie să înlocuiască aceste directoare. Nu rula două instanțe asupra aceleiași baze.

Emiterea ACME și traseul real ChatGPT/VPN trebuie validate pe domeniul și contul operatorului înainte de distribuire. Testele automate folosesc date temporare, API Cloudflare simulat și nu emit certificate publice.
# Blocare după inactivitate și integritate

În **Setări → Blocare după inactivitate (minute)** fiecare proprietar configurează separat vaultul său. Vaulturile noi folosesc 10 minute; valorile salvate anterior sunt păstrate. Sunt acceptate minute întregi între 0 și 1440; 0 dezactivează blocarea automată. Setarea rămâne în vaultul criptat și se păstrează la repornire.

Interacțiunile reale cu interfața și apelurile MCP care folosesc vaultul prelungesc timpul. Pollingul interfeței, `initialize`, `tools/list` și `get_vault_status` nu îl prelungesc. Blocarea șterge cheia activă și invalidează sesiunile UI ale vaultului și aprobările în așteptare. O operație deja trimisă unui server SSH/Kubernetes nu este anulată retroactiv.

MCP oferă `get_vault_status`, cu `locked`, `idle_timeout_minutes`, `idle_expires_at` (Unix milisecunde sau null) și `unlock_url`. Apelurile care necesită un vault blocat returnează `VAULT_LOCKED`, un link și o acțiune `open_url`. Clientul AI poate afișa un buton; clienții fără suport afișează linkul. Forma de prezentare depinde de client. Parola se introduce exclusiv în aplicație, niciodată în conversația MCP.

`npm run build` generează checksumuri pentru dezvoltare; release-ul Windows necesită un manifest semnat Ed25519 în CI. `npm start` verifică fișierele și semnătura configurată înainte de importul aplicației. În timpul rulării, notificările de modificare și verificările periodice declanșează oprirea procesului cu codul 78. Incidentul persistent blochează și pornirile următoare. Configurarea semnării, distribuția cheii publice și recuperarea sunt descrise în [INTEGRITY.md](INTEGRITY.md).

Aceasta detectează modificarea fișierelor față de buildul de încredere. Un atacator care controlează verificatorul și runtime-ul poate ocoli verificarea; o compromitere exclusiv în memorie poate să nu schimbe fișiere. Nu regenera checksumurile pe o instalare suspectă. Reinstalează dintr-o sursă de încredere și protejează directorul aplicației prin permisiunile sistemului. Pentru dezvoltare, `npm run dev` execută sursele și nu oferă garanția verificării prealabile a codului compilat; folosește `npm start` pentru rularea verificată.

