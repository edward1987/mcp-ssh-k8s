# Instalare Windows — MCP SSH K8s

Installerul pentru Windows 10/11 x64 include Node.js. Nu trebuie să instalezi npm sau să clonezi proiectul ca să folosești aplicația. Instalarea cere drepturi de administrator. Componenta WinSW pentru rularea ca serviciu este inclusă în pachet.

## Păstrează baza de date de pe acest calculator

În varianta rulată din surse, datele sunt în folderul `data` de lângă `package.json`. Dacă ai pornit cu variabila `MCP_SSH_DATA`, aceasta stabilește folderul folosit.

Pentru checkout-ul de pe acest calculator, folderul existent este:

```text
D:\apps\mcp-ssh\data
```

1. Oprește aplicația veche, cu **Ctrl+C** în terminalul în care rulează. Nu porni simultan varianta veche și cea instalată.
2. Rulează `mcp-ssh-k8s-0.2.0-windows-x64-setup.exe`.
3. La pagina **Vault-ul și datele tale**, alege **`D:\apps\mcp-ssh\data`**. Alege folderul care conține `vault.json`, nu fișierul în sine. Installerul îl poate detecta dacă se află lângă checkout; altfel folosește Browse.
4. Verifică mesajul **Am găsit un vault existent** și calea afișată în rezumat.
5. Bifează **Pornește automat cu Windows ca serviciu** dacă dorești acest lucru. Opțiunea este debifată implicit la prima instalare.
6. După instalare, deschide **MCP SSH K8s** din Start sau intră la [http://127.0.0.1:7777](http://127.0.0.1:7777).
7. Configureaza administratorul si MFA cu parola master actuala, apoi reconecteaza clientii prin OAuth. Hosturile si credentele SSH sunt pastrate; tokenurile globale sunt invalidate. Vezi [AUTHENTICATION.md](AUTHENTICATION.md).

Installerul nu mută și nu convertește baza. Folosește direct folderul ales și creează înainte de instalare o copie a `vault.json` și `audit.jsonl` în `data\backups\before-install-...`. Păstrează întregul folder; nu șterge checkout-ul dacă ai ales folderul lui `data`.

Pentru independență față de checkout, oprește aplicația, copiază întregul folder `data` într-un loc permanent, de exemplu `D:\MCP-SSH-Data`, și selectează copia în installer. Verifică parola și datele înainte de a șterge sursa. Mediul Python `py` poate necesita reinstalare după mutare; seiful și istoricul nu depind de el.

## Instalare nouă

Folderul propus este `%ProgramData%\MCP SSH K8s\data`. Fișierele aplicației se instalează separat în `%ProgramFiles%\MCP SSH K8s`. La prima deschidere creezi o parolă master de minimum 12 caractere, apoi adaugi sau imporți servere.

În interfață, **Setări → Date locale** arată întotdeauna folderul de date folosit.

## Pornire automată sau manuală

| Alegere în installer | Comportament |
| --- | --- |
| Bifa pentru serviciu este activă | Serviciul **MCP SSH K8s** (`McpSshK8s`) pornește automat, cu pornire întârziată, și la finalul instalării. Rulează sub contul restricționat `LocalService`. |
| Bifa pentru serviciu este inactivă | Aplicația pornește din scurtătura **MCP SSH K8s** și rulează în fundal sub utilizatorul tău. Folosește **Oprește MCP SSH K8s (mod manual)** din Start pentru oprire. |

După fiecare repornire, seiful pornește **blocat**. Introdu parola în browser pentru a permite conexiunile MCP. Installerul nu salvează parola master. Dacă ai activat pornirea automată a tunelului în aplicație, acesta pornește după deblocare.

Admin UI: `http://127.0.0.1:7777`; MCP: `http://127.0.0.1:7778/mcp`. Installerul nu adaugă reguli de firewall și nu expune aplicația pe internet.

Pentru a schimba modul de pornire, rulează din nou installerul, păstrează același folder de date și schimbă bifa. Oprește înainte instanța manuală, dacă există. În mod serviciu, poți opri sau porni aplicația din `services.msc` → **MCP SSH K8s**, cu drepturi de administrator.

## Componente opționale

- Pentru Kubernetes, instalează `kubectl` în PATH-ul **sistemului**, accesibil contului serviciului, apoi repornește serviciul. Kubeconfig-urile cu pluginuri `exec` necesită și acele programe și autentificarea lor în contul care rulează aplicația.
- Importul local din Termius citește profilul Windows și Credential Manager al utilizatorului. Folosește **modul manual**, sub utilizatorul cu Termius instalat, pentru acest import; serviciul `LocalService` nu are acces la profilul tău Termius. După import poți reactiva serviciul fără să schimbi folderul de date. Importul necesită Python 3 și Git, iar configurarea helperului necesită internet.
- Clientul tunelului se descarcă separat din tabul ChatGPT. Dacă există deja în folderul ales `data\bin`, este refolosit.

## Upgrade, dezinstalare și diagnostic

Installerul reține folderul ales în registry (`HKLM\Software\MCP SSH K8s`) și în `install.json` din folderul aplicației. Upgrade-ul oprește serviciul existent, verifică porturile, face backup și îl configurează conform bifei alese. O eroare de port ocupat cere oprirea instanței vechi; installerul nu închide alte programe automat.

Dezinstalarea elimină serviciul și fișierele aplicației. **Baza, istoricul, backupurile și logurile rămân pe disc**. Oprește aplicația manuală înainte de dezinstalare. Pentru a le refolosi, selectează același folder la reinstalare.

Logurile serviciului și ale pornirilor manuale se găsesc în `<folder-date>\logs`. Dacă interfața cere să creezi un seif deși aveai unul, oprește aplicația și reinstalează alegând folderul corect; nu crea alt seif peste datele existente. Parola master nu poate fi recuperată de installer.

### Instalare fără interacțiune

```powershell
# Instalare cu serviciu și bază existentă
.\mcp-ssh-k8s-0.2.0-windows-x64-setup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /TASKS="service" /DATADIR="D:\apps\mcp-ssh\data" /LOG="install.log"

# Instalare în mod manual (fără serviciu)
.\mcp-ssh-k8s-0.2.0-windows-x64-setup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /TASKS="" /DATADIR="D:\MCP-SSH-Data"
```

## Claude Desktop, Codex Desktop și clienții CLI

După deblocarea vault-ului, deschide **Clienți AI**, selectează aplicația și generează configurarea. Sunt disponibile Claude Desktop, Codex Desktop, Codex CLI și Claude CLI (Claude Code). Configurarea Claude Desktop folosește Node.js inclus în installer și puntea locală stdio; nu necesită instalarea separată a Node.js sau descărcarea unui proxy prin npx. Codex Desktop și Codex CLI folosesc aceeași secțiune din `~/.codex/config.toml`.

Copiază configurarea în client, păstrând celelalte intrări, și repornește-l. Serverul trebuie să ruleze, iar vault-ul să fie deblocat. Tokenurile se pot revoca din **Tokenuri MCP**. Configurarea pentru Desktop trebuie generată din instanța instalată; căile unui checkout din surse nu se mută automat în folderul installerului. Vezi [ghidul de conectare](GHID_UTILIZARE.md#8-conectarea-clienților-ai).

## Construirea unui release

Buildul necesită cheia privată Ed25519 din secretul CI `MCP_SSH_INTEGRITY_SIGNING_KEY`; refuză distribuirea unui installer nesemnat la nivel de manifest. Cheia nu intră în Git sau în installer. Vezi [configurarea integrității și recuperarea după incident](INTEGRITY.md). Semnătura manifestului este distinctă de semnătura Authenticode a installerului.

Pe Windows, cu Node.js/npm și Inno Setup 6.3+ instalate:

```powershell
npm ci
npm run release:windows
```

Scriptul rulează testele și build-ul, descarcă versiunile fixate de Node.js și WinSW, verifică SHA-256 și include numai fișierele din lista explicită de distribuție. Produce în `release` installerul, `SHA256SUMS.txt` și `RELEASE-NOTES.md`. Folderul `release\payload` este staging pentru verificare, nu conține date personale și nu este un pachet portabil configurat.

Workflow-ul GitHub Actions permite build manual și atașează fișierele unui release la publicarea unui tag `v<versiune>`. Versiunea tagului trebuie să corespundă cu `package.json`. Installerul nu este semnat cu un certificat de code signing; Windows poate afișa SmartScreen / „Unknown publisher”. Verifică hash-ul publicat înainte de rulare.
